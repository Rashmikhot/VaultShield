"""Dummy values only. These are public demonstration fixtures, never real credentials."""

from shared.schemas import PlainRecord

ACCOUNT_PASSWORD = "Demo account password 42!"
MASTER_PASSPHRASE = "Demo master passphrase four words 83!"
RECORDS = [
    PlainRecord(
        title="DUMMY-TITLE-4a31 VaultShield",
        username="DUMMY-USER-6b42@example.test",
        password="DUMMY-SECRET-8c53-never-real",
        url="https://dummy-website.example.test",
        notes="DUMMY-NOTE-0d64 ಕನ್ನಡ 🔐",
    ),
    PlainRecord(
        title="Demo API token",
        username="dummy-service",
        password="dummy_api_token_12345",
        notes="This token grants access to nothing.",
    ),
]
