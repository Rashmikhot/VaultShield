import argparse
from datetime import datetime, timezone
from client.api import VaultAPI
from client.service import VaultService
from scripts.dummy_data import ACCOUNT_PASSWORD, MASTER_PASSPHRASE, RECORDS


def seed(api, email):
    service = VaultService(api)
    service.register(email, ACCOUNT_PASSWORD)
    service.login(email, ACCOUNT_PASSWORD)
    service.setup(MASTER_PASSPHRASE)
    for record in RECORDS:
        service.save_record(record)
    return service


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create a NEW dummy-only demonstration account over verified HTTPS"
    )
    parser.add_argument("--server", default="https://localhost:8443")
    parser.add_argument("--ca", default="deploy/certs/ca.crt")
    parser.add_argument(
        "--email", default="demo-" + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S") + "@example.test"
    )
    args = parser.parse_args()
    api = VaultAPI(args.server, args.ca)
    try:
        service = seed(api, args.email)
        print(f"Dummy account created: {args.email}")
        print("Public demo account password:", ACCOUNT_PASSWORD)
        print("Public demo master passphrase:", MASTER_PASSPHRASE)
        print("Records created:", len(service.records))
        service.logout()
    finally:
        api.close()
