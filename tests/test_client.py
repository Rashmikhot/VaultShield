import threading
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from client.api import APIError, VaultAPI
from client.service import VaultService, LockedError
from client.crypto import VaultIntegrityError
from server.app import create_app
from server.config import Settings
from server.models import Record
from shared.schemas import PlainRecord
from tests.conftest import ACCOUNT_PASSWORD, MASTER


class InProcessAPI:
    """Test-only adapter; the shipped desktop transport has no HTTP bypass."""

    def __init__(self, client):
        self.client, self.token, self.tls_info = client, None, None
        self.base_url = "https://in-process.test"
        self.sent = []

    def request(self, method, path, data=None):
        self.sent.append((method, path, data))
        h = {"Authorization": "Bearer " + self.token} if self.token else {}
        response = self.client.request(method, path, json=data, headers=h)
        if response.status_code >= 300:
            raise APIError(response.status_code, "Test request rejected")
        return response.json() if response.content else None

    def logout(self):
        try:
            self.request("POST", "/auth/logout")
        finally:
            self.token = None


def ready(client):
    service = VaultService(InProcessAPI(client))
    service.register("alice@example.test", ACCOUNT_PASSWORD)
    assert not service.login("alice@example.test", ACCOUNT_PASSWORD)
    service.setup(MASTER)
    return service


def test_client_full_lifecycle_and_restart(backend):
    app, c, _, path = backend
    service = ready(c)
    plain = PlainRecord(title="Client demo", password="client-secret-47", notes="ಕನ್ನಡ")
    rid = service.save_record(plain)
    edited = plain.model_copy(update={"title": "Edited locally"})
    service.save_record(edited, rid)
    assert service.records[rid][0].revision == 2
    service.lock()
    assert service.key is None and not service.records
    with pytest.raises(LockedError):
        service.save_record(plain)
    with pytest.raises(VaultIntegrityError):
        service.unlock("Wrong master passphrase 47!")
    service.unlock(MASTER)
    assert service.records[rid][1] == edited
    key = service.key
    service.change_master(MASTER, MASTER + " changed")
    assert service.key == key
    service.logout()
    assert service.api.token is None and service.key is None
    # New application instance and new client using the same migrated database.
    restarted = create_app(Settings(database_url="sqlite:///" + str(path)))
    with TestClient(restarted) as new_client:
        fresh = VaultService(InProcessAPI(new_client))
        assert fresh.login("alice@example.test", ACCOUNT_PASSWORD)
        fresh.unlock(MASTER + " changed")
        assert fresh.key == key and fresh.records[rid][1] == edited
        fresh.delete_record(rid)
        fresh.refresh()
        assert fresh.records == {}
    restarted.state.engine.dispose()
    # Vault master and decrypted records never occur in outgoing request JSON.
    import json

    outgoing = json.dumps(service.api.sent)
    assert MASTER not in outgoing
    assert plain.password not in outgoing and plain.notes not in outgoing


def test_failed_refresh_does_not_expose_partial_plaintext(backend):
    app, c, _, _ = backend
    service = ready(c)
    service.save_record(PlainRecord(title="Good record"))
    bad = service.save_record(PlainRecord(title="Tampered record"))
    with app.state.sessions() as db:
        row = db.get(Record, bad)
        row.ciphertext = bytes([row.ciphertext[0] ^ 1]) + row.ciphertext[1:]
        db.commit()
    with pytest.raises(VaultIntegrityError):
        service.refresh()
    assert service.key is None and service.records == {}


def test_lock_during_inflight_unlock_prevents_repopulation(backend):
    _, c, _, _ = backend
    service = ready(c)
    service.lock()
    original = service.api.request
    entered, release = threading.Event(), threading.Event()

    def delayed(method, path, data=None):
        result = original(method, path, data)
        if path.endswith("/envelope"):
            entered.set()
            assert release.wait(10)
        return result

    service.api.request = delayed
    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(service.unlock, MASTER)
        assert entered.wait(10)
        service.lock()
        release.set()
        with pytest.raises(LockedError):
            future.result()
    assert service.key is None and service.records == {}


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8000",
        "https://user:pass@localhost",
        "https://localhost/path",
        "https://localhost?query=x",
    ],
)
def test_transport_rejects_insecure_or_ambiguous_origins(url):
    with pytest.raises(ValueError):
        VaultAPI(url)


def test_migration_drift_and_schema(backend, monkeypatch):
    from alembic import command
    from alembic.config import Config

    _, _, _, path = backend
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", "sqlite:///" + str(path))
    command.check(cfg)


def test_account_change_through_client_clears_local_state(backend):
    _, c, _, _ = backend
    service = ready(c)
    service.change_account_password(ACCOUNT_PASSWORD, "New account password 82!")
    assert service.api.token is None and service.key is None and service.vault is None
    assert not service.records and service.user_id is None
    assert service.login("alice@example.test", "New account password 82!")
    service.unlock(MASTER)
    assert service.key is not None


def test_transport_logout_failure_clears_token(monkeypatch):
    api = VaultAPI()
    api.token = "dummy-token"

    def fail(*_):
        raise APIError(0, "Network failed")

    monkeypatch.setattr(api, "request", fail)
    with pytest.raises(APIError, match="revocation was not confirmed"):
        api.logout()
    assert api.token is None
    api.close()
