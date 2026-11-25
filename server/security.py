import hashlib
import secrets
import threading
import time
from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from shared.schemas import MIN_ITERATIONS, MAX_ITERATIONS


def verifier(password, salt, iterations=MIN_ITERATIONS):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(
        password.encode("utf-8")
    )


def new_password(password):
    salt = secrets.token_bytes(16)
    return dict(
        password_algorithm="PBKDF2-HMAC-SHA256",
        password_salt=salt,
        password_iterations=MIN_ITERATIONS,
        password_verifier=verifier(password, salt),
    )


def check_password(password, user):
    if (
        user.password_algorithm != "PBKDF2-HMAC-SHA256"
        or not MIN_ITERATIONS <= user.password_iterations <= MAX_ITERATIONS
        or len(user.password_salt) != 16
        or len(user.password_verifier) != 32
    ):
        return False
    try:
        PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=user.password_salt, iterations=user.password_iterations
        ).verify(password.encode("utf-8"), user.password_verifier)
        return True
    except InvalidKey:
        return False


def token_hash(token):
    return hashlib.sha256(token.encode("ascii")).hexdigest()


class RateLimiter:
    """Bounded single-process fixed windows. Gateway adds per-IP throttling."""

    def __init__(self, clock=time.monotonic, capacity=10_000):
        self.clock, self.capacity = clock, capacity
        self.entries = {}
        self.lock = threading.Lock()

    def allow(self, key, limit, window=60):
        now = self.clock()
        with self.lock:
            self.entries = {k: v for k, v in self.entries.items() if v[0] > now}
            end, count = self.entries.get(key, (now + window, 0))
            if count >= limit or (key not in self.entries and len(self.entries) >= self.capacity):
                return False
            self.entries[key] = (end, count + 1)
            return True
