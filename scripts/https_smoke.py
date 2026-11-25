"""Full client lifecycle over the configured HTTPS endpoint, using a new dummy account."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from client.api import VaultAPI, APIError
from client.service import VaultService
from scripts.seed_demo import seed
from scripts.dummy_data import ACCOUNT_PASSWORD, MASTER_PASSPHRASE


def run(server, ca):
    api = VaultAPI(server, ca)
    checks = {}
    try:
        service = seed(api, "smoke-" + str(uuid4()) + "@example.test")
        email, rid = service.email, next(iter(service.records))
        plain = service.records[rid][1]
        checks["created_two_dummy_records"] = len(service.records) == 2
        service.lock()
        service.unlock(MASTER_PASSPHRASE)
        checks["unlock_roundtrip"] = service.records[rid][1] == plain
        service.save_record(plain.model_copy(update={"notes": "Updated dummy note"}), rid)
        service.refresh()
        checks["edit_synced"] = service.records[rid][0].revision == 2
        service.change_master(MASTER_PASSPHRASE, MASTER_PASSPHRASE + " changed")
        service.lock()
        service.unlock(MASTER_PASSPHRASE + " changed")
        checks["rewrap_and_unlock"] = service.records[rid][0].revision == 2
        service.delete_record(rid)
        service.refresh()
        checks["delete_synced"] = rid not in service.records
        old_token = api.token
        service.logout()
        api.token = old_token
        try:
            api.request("GET", "/vaults")
            checks["logout_revoked"] = False
        except APIError as error:
            checks["logout_revoked"] = error.status == 401
        api.token = None
        fresh = VaultService(api)
        fresh.login(email, ACCOUNT_PASSWORD)
        fresh.unlock(MASTER_PASSPHRASE + " changed")
        checks["new_client_reunlock"] = len(fresh.records) == 1
        fresh.logout()
        return {
            "time_utc": datetime.now(timezone.utc).isoformat(),
            "server": server,
            "checks": checks,
            "observed_tls": api.tls_info,
            "scope": "Live HTTPS API and real client service; no Tkinter mouse interaction.",
        }
    finally:
        api.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", default="https://localhost:8443")
    parser.add_argument("--ca", default="deploy/certs/ca.crt")
    parser.add_argument("--out", default="evidence/https-smoke.json")
    args = parser.parse_args()
    result = run(args.server, args.ca)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if all(result["checks"].values()) else 1)
