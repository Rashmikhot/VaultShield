from uuid import uuid4
import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from server.app import create_app
from server.config import Settings
from client.crypto import generate_key, wrap_key, encrypt_record
from shared.schemas import PlainRecord

ACCOUNT_PASSWORD = "Demo-account-password-47!"
MASTER = "Demo master passphrase four words 29!"


@pytest.fixture
def backend(tmp_path, monkeypatch):
    monkeypatch.delenv("VS_DATABASE_URL", raising=False)
    url = "sqlite:///" + str(tmp_path / "test.db")
    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    now = [1_800_000_000]
    app = create_app(Settings(database_url=url), clock=lambda: now[0])
    with TestClient(app) as client:
        yield app, client, now, tmp_path / "test.db"
    app.state.engine.dispose()


def register(client, email="alice@example.test"):
    payload = {"email": email, "password": ACCOUNT_PASSWORD}
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 201, response.text
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 200
    return response.json(), {"Authorization": "Bearer " + response.json()["token"]}


def seed(client, email="alice@example.test"):
    user, headers = register(client, email)
    key, vid = generate_key(), str(uuid4())
    envelope = wrap_key(key, MASTER, user["user_id"], vid)
    response = client.post("/vaults", headers=headers, json={"id": vid, "envelope": envelope.model_dump()})
    assert response.status_code == 201, response.text
    plain = PlainRecord(
        title="UNIQUE-TITLE-7e91f0",
        username="UNIQUE-USER-8f20ab",
        password="UNIQUE-SECRET-9a31bc",
        url="https://UNIQUE-URL-0b42cd.example",
        notes="UNIQUE-NOTE-1c53de ಕನ್ನಡ 🌊",
    )
    rid = str(uuid4())
    record = encrypt_record(key, user["user_id"], vid, rid, 1, plain)
    response = client.post(f"/vaults/{vid}/records", headers=headers, json=record.model_dump())
    assert response.status_code == 201, response.text
    return {
        "user": user,
        "headers": headers,
        "key": key,
        "vid": vid,
        "rid": rid,
        "envelope": envelope,
        "record": record,
        "plain": plain,
    }
