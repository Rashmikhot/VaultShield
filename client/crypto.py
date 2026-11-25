"""All vault encryption occurs here, on the client. No hand-rolled primitives."""

import json
import secrets
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from shared.schemas import (
    Envelope,
    RecordWrite,
    PlainRecord,
    MIN_ITERATIONS,
    MAX_ITERATIONS,
    MAX_PLAINTEXT,
    b64decode,
    b64encode,
    uuid_text,
)


class VaultIntegrityError(ValueError):
    """Wrong passphrase or modified data; no unauthenticated plaintext is returned."""


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def generate_key() -> bytes:
    return secrets.token_bytes(32)


def derive_key(passphrase: str, salt: bytes, iterations: int) -> bytes:
    if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 256:
        raise ValueError("Use a master passphrase of 12–256 characters")
    if len(salt) != 16 or type(iterations) is not int or not MIN_ITERATIONS <= iterations <= MAX_ITERATIONS:
        raise ValueError("Unsupported KDF parameters")
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations).derive(
        passphrase.encode("utf-8")
    )


def envelope_aad(account_id: str, vault_id: str, envelope: Envelope) -> bytes:
    return canonical(
        {
            "domain": "VaultShield/envelope",
            "aad_version": 1,
            "account_id": uuid_text(account_id),
            "vault_id": uuid_text(vault_id),
            **envelope.model_dump(exclude={"nonce", "wrapped_key"}),
        }
    )


def record_aad(account_id: str, vault_id: str, record: RecordWrite) -> bytes:
    return canonical(
        {
            "domain": "VaultShield/record",
            "aad_version": 1,
            "account_id": uuid_text(account_id),
            "vault_id": uuid_text(vault_id),
            "record_id": record.id,
            "schema_version": record.schema_version,
            "key_version": record.key_version,
            "revision": record.revision,
        }
    )


def wrap_key(
    key: bytes,
    passphrase: str,
    account_id: str,
    vault_id: str,
    revision: int = 1,
    iterations: int = MIN_ITERATIONS,
) -> Envelope:
    if len(key) != 32:
        raise ValueError("Invalid vault key length")
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    wrapping = derive_key(passphrase, salt, iterations)
    envelope = Envelope(
        envelope_revision=revision,
        kdf_iterations=iterations,
        salt=b64encode(salt),
        nonce=b64encode(nonce),
        wrapped_key=b64encode(bytes(48)),
    )
    encrypted = AESGCM(wrapping).encrypt(nonce, key, envelope_aad(account_id, vault_id, envelope))
    return envelope.model_copy(update={"wrapped_key": b64encode(encrypted)})


def unwrap_key(envelope: Envelope, passphrase: str, account_id: str, vault_id: str) -> bytes:
    envelope = Envelope.model_validate(envelope.model_dump())
    wrapping = derive_key(passphrase, b64decode(envelope.salt), envelope.kdf_iterations)
    try:
        return AESGCM(wrapping).decrypt(
            b64decode(envelope.nonce),
            b64decode(envelope.wrapped_key),
            envelope_aad(account_id, vault_id, envelope),
        )
    except InvalidTag:
        raise VaultIntegrityError("Unable to unlock: wrong passphrase or altered envelope") from None


def encrypt_record(
    key: bytes, account_id: str, vault_id: str, record_id: str, revision: int, plaintext: PlainRecord
) -> RecordWrite:
    if len(key) != 32:
        raise ValueError("Invalid vault key length")
    plaintext = PlainRecord.model_validate(plaintext.model_dump())
    raw = canonical(plaintext.model_dump())
    if len(raw) > MAX_PLAINTEXT:
        raise ValueError("Record exceeds 32 KiB serialized limit")
    record = RecordWrite(
        id=record_id,
        revision=revision,
        nonce=b64encode(secrets.token_bytes(12)),
        ciphertext=b64encode(bytes(16)),
    )
    encrypted = AESGCM(key).encrypt(b64decode(record.nonce), raw, record_aad(account_id, vault_id, record))
    return record.model_copy(update={"ciphertext": b64encode(encrypted)})


def decrypt_record(key: bytes, account_id: str, vault_id: str, record: RecordWrite) -> PlainRecord:
    if len(key) != 32:
        raise ValueError("Invalid vault key length")
    record = RecordWrite.model_validate({k: getattr(record, k) for k in RecordWrite.model_fields})
    try:
        raw = AESGCM(key).decrypt(
            b64decode(record.nonce), b64decode(record.ciphertext), record_aad(account_id, vault_id, record)
        )
        return PlainRecord.model_validate_json(raw)
    except (InvalidTag, ValueError):
        raise VaultIntegrityError("Record authentication or format validation failed") from None
