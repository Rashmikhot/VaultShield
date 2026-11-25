import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = "sqlite:///./vaultshield.db"
    session_seconds: int = 1800
    login_attempts: int = 10
    max_request_bytes: int = 65_536

    @classmethod
    def from_env(cls):
        seconds = int(os.getenv("VS_SESSION_SECONDS", "1800"))
        if not 60 <= seconds <= 86400:
            raise ValueError("VS_SESSION_SECONDS must be 60–86400")
        return cls(database_url=os.getenv("VS_DATABASE_URL", cls.database_url), session_seconds=seconds)
