"""UI-independent client state. Secrets remain in process memory only."""

import hmac
import threading
from uuid import uuid4
from client.crypto import (
    generate_key,
    wrap_key,
    unwrap_key,
    encrypt_record,
    decrypt_record,
    VaultIntegrityError,
)
from shared.schemas import Credentials, VaultView, RecordView, RecordWrite, PlainRecord, uuid_text


class LockedError(RuntimeError):
    pass


class VaultService:
    def __init__(self, api):
        self.api = api
        self.user_id = self.email = None
        self.vault = None
        self.key = None
        self.records = {}
        self.generation = 0
        self.mutex = threading.RLock()

    def lock(self):
        with self.mutex:
            self.generation += 1
            self.key = None
            self.records.clear()

    def _snapshot(self, require_key=True):
        with self.mutex:
            if require_key and self.key is None:
                raise LockedError("Vault is locked")
            return self.generation, self.key, self.vault

    def _commit(self, generation, **values):
        with self.mutex:
            if generation != self.generation:
                raise LockedError("Operation finished after the vault was locked")
            for name, value in values.items():
                setattr(self, name, value)

    def register(self, email, password):
        body = Credentials(email=email, password=password)
        return self.api.request("POST", "/auth/register", body.model_dump())

    def login(self, email, password):
        self.lock()
        self.api.token = None
        body = Credentials(email=email, password=password)
        result = self.api.request("POST", "/auth/login", body.model_dump())
        self.user_id = uuid_text(result["user_id"])
        self.email = result["email"]
        self.api.token = result["token"]
        self.vault = None
        vaults = self.api.request("GET", "/vaults")
        if not isinstance(vaults, list) or len(vaults) > 1:
            raise VaultIntegrityError("Invalid vault list")
        if vaults:
            self.vault = self._validate_vault(vaults[0])
        return bool(self.vault)

    def _validate_vault(self, value, expected_id=None):
        vault = VaultView.model_validate(value)
        if vault.owner_id != self.user_id or (expected_id and vault.id != expected_id):
            raise VaultIntegrityError("Vault identity mismatch")
        return vault

    def setup(self, passphrase):
        generation, _, _ = self._snapshot(False)
        vault_id, key = str(uuid4()), generate_key()
        envelope = wrap_key(key, passphrase, self.user_id, vault_id)
        data = self.api.request("POST", "/vaults", {"id": vault_id, "envelope": envelope.model_dump()})
        vault = self._validate_vault(data, vault_id)
        if vault.envelope != envelope:
            raise VaultIntegrityError("Unexpected stored key envelope")
        self._commit(generation, vault=vault, key=key, records={})

    def unlock(self, passphrase):
        generation, _, vault = self._snapshot(False)
        if not vault:
            raise LockedError("Create a vault first")
        data = self.api.request("GET", f"/vaults/{vault.id}/envelope")
        current = self._validate_vault(data, vault.id)
        if current.envelope.envelope_revision < vault.envelope.envelope_revision:
            raise VaultIntegrityError("Older envelope detected in this session")
        key = unwrap_key(current.envelope, passphrase, self.user_id, vault.id)
        self._commit(generation, key=key, vault=current)
        try:
            self.refresh()
        except Exception:
            self.lock()
            raise

    def refresh(self):
        generation, key, vault = self._snapshot()
        decrypted, after = {}, None
        try:
            for _ in range(100):
                self._commit(generation)
                path = f"/vaults/{vault.id}/records?limit=100" + (f"&after={after}" if after else "")
                page = self.api.request("GET", path)
                if not isinstance(page, list) or len(page) > 100:
                    raise VaultIntegrityError("Invalid record list")
                for data in page:
                    record = RecordView.model_validate(data)
                    if record.owner_id != self.user_id or record.vault_id != vault.id:
                        raise VaultIntegrityError("Record identity mismatch")
                    if record.id in decrypted or (after and record.id <= after):
                        raise VaultIntegrityError("Invalid record ordering")
                    previous = self.records.get(record.id)
                    if previous and record.revision < previous[0].revision:
                        raise VaultIntegrityError("Older record detected in this session")
                    decrypted[record.id] = (record, decrypt_record(key, self.user_id, vault.id, record))
                    after = record.id
                if len(page) < 100:
                    self._commit(generation, records=decrypted)
                    return
            raise VaultIntegrityError("Vault exceeds the 10,000-record client limit")
        except Exception:
            self.lock()
            raise

    def save_record(self, plain: PlainRecord, record_id=None):
        generation, key, vault = self._snapshot()
        if record_id:
            old = self.records[record_id][0]
            revision = old.revision + 1
        else:
            record_id, revision = str(uuid4()), 1
        encrypted = encrypt_record(key, self.user_id, vault.id, record_id, revision, plain)
        path = f"/vaults/{vault.id}/records"
        if revision == 1:
            result = self.api.request("POST", path, encrypted.model_dump())
        else:
            result = self.api.request(
                "PUT",
                path + "/" + record_id,
                {"expected_revision": revision - 1, "record": encrypted.model_dump()},
            )
        stored = RecordView.model_validate(result)
        if (
            stored.owner_id != self.user_id
            or stored.vault_id != vault.id
            or any(getattr(stored, k) != getattr(encrypted, k) for k in RecordWrite.model_fields)
        ):
            raise VaultIntegrityError("Unexpected record acknowledgement")
        with self.mutex:
            records = dict(self.records)
            records[record_id] = (stored, plain)
            self._commit(generation, records=records)
        return record_id

    def delete_record(self, record_id):
        generation, _, vault = self._snapshot()
        revision = self.records[record_id][0].revision
        self.api.request("DELETE", f"/vaults/{vault.id}/records/{record_id}?expected_revision={revision}")
        with self.mutex:
            records = dict(self.records)
            records.pop(record_id, None)
            self._commit(generation, records=records)

    def change_master(self, old_passphrase, new_passphrase):
        generation, key, vault = self._snapshot()
        current = self._validate_vault(self.api.request("GET", f"/vaults/{vault.id}/envelope"), vault.id)
        verified = unwrap_key(current.envelope, old_passphrase, self.user_id, vault.id)
        if not hmac.compare_digest(verified, key):
            raise VaultIntegrityError("Vault key mismatch; lock and unlock again")
        envelope = wrap_key(
            key, new_passphrase, self.user_id, vault.id, revision=current.envelope.envelope_revision + 1
        )
        result = self.api.request(
            "PUT",
            f"/vaults/{vault.id}/envelope",
            {"expected_revision": current.envelope.envelope_revision, "envelope": envelope.model_dump()},
        )
        changed = self._validate_vault(result, vault.id)
        if changed.envelope != envelope:
            raise VaultIntegrityError("Unexpected envelope acknowledgement")
        self._commit(generation, vault=changed)

    def change_account_password(self, current, new):
        self.api.request("POST", "/auth/password", {"current_password": current, "new_password": new})
        self.lock()
        self.api.token = None
        self.user_id = self.email = self.vault = None

    def logout(self):
        self.lock()
        try:
            self.api.logout()
        finally:
            self.user_id = self.email = self.vault = None
