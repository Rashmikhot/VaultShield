from uuid import uuid4
import pytest
from pydantic import ValidationError
from client.crypto import (
    generate_key,
    wrap_key,
    unwrap_key,
    encrypt_record,
    decrypt_record,
    VaultIntegrityError,
    record_aad,
    canonical,
    derive_key,
)
from shared.schemas import PlainRecord, Envelope, b64decode, b64encode
from tests.conftest import MASTER


@pytest.fixture
def encrypted():
    uid, vid, rid = (str(uuid4()) for _ in range(3))
    key = generate_key()
    plain = PlainRecord(
        title="ಕನ್ನಡ 🔐",
        username="用户@example.test",
        password="秘密 🌊 é e\u0301",
        notes="line one\nline two",
    )
    return key, uid, vid, plain, encrypt_record(key, uid, vid, rid, 1, plain)


def test_unicode_round_trip(encrypted):
    key, uid, vid, plain, record = encrypted
    assert decrypt_record(key, uid, vid, record) == plain
    env = wrap_key(key, MASTER, uid, vid)
    assert unwrap_key(env, MASTER, uid, vid) == key


def test_wrong_passphrase(encrypted):
    key, uid, vid, _, _ = encrypted
    env = wrap_key(key, MASTER, uid, vid)
    with pytest.raises(VaultIntegrityError):
        unwrap_key(env, "Wrong master passphrase!", uid, vid)


@pytest.mark.parametrize("part,index", [("ciphertext", 0), ("ciphertext", -1), ("nonce", 0)])
def test_tamper_ciphertext_tag_nonce(encrypted, part, index):
    key, uid, vid, _, record = encrypted
    data = bytearray(b64decode(getattr(record, part)))
    data[index] ^= 1
    changed = record.model_copy(update={part: b64encode(data)})
    with pytest.raises(VaultIntegrityError):
        decrypt_record(key, uid, vid, changed)


@pytest.mark.parametrize("field", ["account", "vault", "id", "revision"])
def test_aad_substitution(encrypted, field):
    key, uid, vid, _, record = encrypted
    if field == "account":
        uid = str(uuid4())
    elif field == "vault":
        vid = str(uuid4())
    else:
        record = record.model_copy(update={field: str(uuid4()) if field == "id" else 2})
    with pytest.raises(VaultIntegrityError):
        decrypt_record(key, uid, vid, record)


@pytest.mark.parametrize("field", ["schema_version", "key_version"])
def test_unsupported_record_versions(encrypted, field):
    key, uid, vid, _, record = encrypted
    with pytest.raises(ValidationError):
        decrypt_record(key, uid, vid, record.model_copy(update={field: 2}))


@pytest.mark.parametrize("field", ["nonce", "wrapped_key", "salt", "envelope_revision", "kdf_iterations"])
def test_envelope_tamper(encrypted, field):
    key, uid, vid, _, _ = encrypted
    env = wrap_key(key, MASTER, uid, vid)
    value = getattr(env, field)
    if isinstance(value, str):
        raw = bytearray(b64decode(value))
        raw[0] ^= 1
        value = b64encode(raw)
    else:
        value += 1
    with pytest.raises(VaultIntegrityError):
        unwrap_key(env.model_copy(update={field: value}), MASTER, uid, vid)


def test_envelope_identity_substitution(encrypted):
    key, uid, vid, _, _ = encrypted
    env = wrap_key(key, MASTER, uid, vid)
    with pytest.raises(VaultIntegrityError):
        unwrap_key(env, MASTER, str(uuid4()), vid)
    with pytest.raises(VaultIntegrityError):
        unwrap_key(env, MASTER, uid, str(uuid4()))


def test_random_encryption_sampling(encrypted):
    key, uid, vid, plain, record = encrypted
    samples = [encrypt_record(key, uid, vid, record.id, 1, plain) for _ in range(1000)]
    assert len({r.nonce for r in samples}) == 1000
    assert len({r.ciphertext for r in samples}) == 1000
    # Regression sampling only: not a mathematical guarantee of no nonce collisions.


def test_rewrap_preserves_key_and_changes_random_material(encrypted):
    key, uid, vid, _, record = encrypted
    first = wrap_key(key, MASTER, uid, vid)
    second = wrap_key(key, MASTER + " new", uid, vid, 2)
    assert first.salt != second.salt and first.nonce != second.nonce
    assert unwrap_key(second, MASTER + " new", uid, vid) == key
    assert decrypt_record(key, uid, vid, record)
    # A stolen old envelope still works with the old master passphrase.
    assert unwrap_key(first, MASTER, uid, vid) == key


@pytest.mark.parametrize("iterations", [0, 599999, 2000001, 10**15, True])
def test_kdf_bounds(iterations):
    with pytest.raises(ValueError):
        derive_key(MASTER, bytes(16), iterations)


def test_format_and_size_validation(encrypted):
    key, uid, vid, _, _ = encrypted
    env = wrap_key(key, MASTER, uid, vid).model_dump()
    env["format_version"] = 2
    with pytest.raises(ValidationError):
        Envelope(**env)
    with pytest.raises(ValueError):
        encrypt_record(key, uid, vid, str(uuid4()), 1, PlainRecord(title="x", notes="🌊" * 16000))


def test_deterministic_aad(encrypted):
    _, uid, vid, _, record = encrypted
    assert canonical({"z": 1, "a": "x"}) == b'{"a":"x","z":1}'
    aad = record_aad(uid, vid, record)
    for item in (uid, vid, record.id, "schema_version", "key_version", "revision", "aad_version"):
        assert item.encode() in aad


@pytest.mark.parametrize("field", ["schema_version", "key_version"])
def test_boolean_versions_are_rejected(encrypted, field):
    key, uid, vid, _, record = encrypted
    with pytest.raises(ValidationError):
        decrypt_record(key, uid, vid, record.model_copy(update={field: True}))
