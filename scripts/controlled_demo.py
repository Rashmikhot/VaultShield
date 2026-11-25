"""Attack demonstrations use newly generated, disposable databases only.
There is deliberately no argument accepting an existing database to mutate.
"""

import argparse
import json
import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from client.crypto import decrypt_record, VaultIntegrityError
from client.service import VaultService
from scripts.dummy_data import ACCOUNT_PASSWORD, MASTER_PASSPHRASE, RECORDS
from server.app import create_app
from server.config import Settings
from shared.schemas import RecordWrite, b64encode


class DemoTransport:
    """In-process demonstration transport; never used by the desktop application."""

    def __init__(self, client):
        self.client, self.token = client, None

    def request(self, method, path, data=None):
        h = {"Authorization": "Bearer " + self.token} if self.token else {}
        response = self.client.request(method, path, headers=h, json=data)
        response.raise_for_status()
        return response.json() if response.content else None


def read_record(path, rid):
    with sqlite3.connect(path) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("SELECT * FROM records WHERE id=?", (rid,)).fetchone()
        return RecordWrite(
            id=row["id"],
            ciphertext=b64encode(row["ciphertext"]),
            nonce=b64encode(row["nonce"]),
            revision=row["revision"],
            schema_version=row["schema_version"],
            key_version=row["key_version"],
        )


def run():
    checks = {}
    with tempfile.TemporaryDirectory(prefix="vaultshield-dummy-demo-") as temp:
        root = Path(temp)
        original = root / "original.db"
        url = "sqlite:///" + str(original)
        # env.py honors VS_DATABASE_URL; force the disposable URL for this command only.
        import os

        previous = os.environ.pop("VS_DATABASE_URL", None)
        try:
            cfg = Config("alembic.ini")
            cfg.set_main_option("sqlalchemy.url", url)
            command.upgrade(cfg, "head")
        finally:
            if previous is not None:
                os.environ["VS_DATABASE_URL"] = previous
        app = create_app(Settings(database_url=url))
        with TestClient(app) as client:
            service = VaultService(DemoTransport(client))
            service.register("dummy-owner@example.test", ACCOUNT_PASSWORD)
            service.login("dummy-owner@example.test", ACCOUNT_PASSWORD)
            service.setup(MASTER_PASSPHRASE)
            rid = service.save_record(RECORDS[0])
            other = service.save_record(RECORDS[1])
            uid, vid, key = service.user_id, service.vault.id, service.key
            # sqlite backup makes a consistent leak copy; never mutate original.
            leak = root / "database-leak-copy.db"
            with sqlite3.connect(original) as source, sqlite3.connect(leak) as target:
                source.backup(target)
            raw = leak.read_bytes()
            checks["database_seeded_plaintext_absent"] = all(
                value.encode() not in raw for value in RECORDS[0].model_dump().values()
            )
            checks["master_and_plaintext_key_absent"] = (
                MASTER_PASSPHRASE.encode() not in raw and key not in raw
            )
            for field, index in [("ciphertext", 0), ("ciphertext", -1), ("nonce", 0)]:
                copy = root / f"tamper-{field}-{index}.db"
                shutil.copy2(leak, copy)
                with sqlite3.connect(copy) as db:
                    data = bytearray(
                        db.execute(f"SELECT {field} FROM records WHERE id=?", (rid,)).fetchone()[0]
                    )
                    data[index] ^= 1
                    db.execute(f"UPDATE records SET {field}=? WHERE id=?", (bytes(data), rid))
                    db.commit()
                try:
                    decrypt_record(key, uid, vid, read_record(copy, rid))
                    checks[f"tamper_{field}_{index}_rejected"] = False
                except VaultIntegrityError:
                    checks[f"tamper_{field}_{index}_rejected"] = True
            copy = root / "substitution-copy.db"
            shutil.copy2(leak, copy)
            with sqlite3.connect(copy) as db:
                source = db.execute("SELECT ciphertext, nonce FROM records WHERE id=?", (rid,)).fetchone()
                db.execute("UPDATE records SET ciphertext=?, nonce=? WHERE id=?", (*source, other))
                db.commit()
            try:
                decrypt_record(key, uid, vid, read_record(copy, other))
                checks["record_substitution_rejected"] = False
            except VaultIntegrityError:
                checks["record_substitution_rejected"] = True
            bob = VaultService(DemoTransport(client))
            bob.register("dummy-intruder@example.test", ACCOUNT_PASSWORD)
            bob.login("dummy-intruder@example.test", ACCOUNT_PASSWORD)
            h = {"Authorization": "Bearer " + bob.api.token}
            checks["unauthorized_read_404"] = (
                client.get(f"/vaults/{vid}/records/{rid}", headers=h).status_code == 404
            )
            checks["unauthorized_delete_404"] = (
                client.delete(f"/vaults/{vid}/records/{rid}?expected_revision=1", headers=h).status_code
                == 404
            )
            service.lock()
            service.unlock(MASTER_PASSPHRASE)
            checks["original_data_unmodified"] = service.records[rid][1] == RECORDS[0]
        app.state.engine.dispose()
    return {
        "time_utc": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "scope": "In-process API; disposable dummy database and independent leak/tamper copies. No TLS claim.",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="evidence/controlled-demo.json")
    args = parser.parse_args()
    report = run()
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if all(report["checks"].values()) else 1)
