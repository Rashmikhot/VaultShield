"""Wire formats. Strict types, canonical base64/UUIDs and bounded work factors."""

import base64
import binascii
import re
from typing import Annotated, Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, AfterValidator, model_validator, field_validator

MIN_ITERATIONS = 600_000
MAX_ITERATIONS = 2_000_000
MAX_PLAINTEXT = 32_768
MAX_CIPHERTEXT = MAX_PLAINTEXT + 16
MAX_REVISION = 2_147_483_647


def uuid_text(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("UUID must be canonical lowercase")
    return value


def b64decode(value: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Invalid base64") from exc
    if base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("Non-canonical base64")
    return raw


def b64encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def sized_b64(minimum, maximum):
    def validate(value):
        if not minimum <= len(b64decode(value)) <= maximum:
            raise ValueError("Invalid encoded length")
        return value

    return validate


ID = Annotated[str, Field(min_length=36, max_length=36), AfterValidator(uuid_text)]
Nonce = Annotated[str, Field(max_length=16), AfterValidator(sized_b64(12, 12))]
Salt = Annotated[str, Field(max_length=24), AfterValidator(sized_b64(16, 16))]
Ciphertext = Annotated[str, Field(max_length=43_712), AfterValidator(sized_b64(16, MAX_CIPHERTEXT))]
WrappedKey = Annotated[str, Field(max_length=64), AfterValidator(sized_b64(48, 48))]
Revision = Annotated[int, Field(ge=1, le=MAX_REVISION)]
Password = Annotated[str, Field(min_length=12, max_length=256)]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, hide_input_in_errors=True)

    @field_validator("format_version", "key_version", "schema_version", mode="before", check_fields=False)
    @classmethod
    def integer_versions(cls, value):
        if type(value) is not int:
            raise ValueError("Version must be an integer")
        return value


class Credentials(StrictModel):
    email: str = Field(min_length=3, max_length=254)
    password: Password

    @model_validator(mode="after")
    def email_valid(self):
        self.email = self.email.strip().lower()
        if not re.fullmatch(r"[a-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[a-z0-9.-]+\.[a-z]{2,63}", self.email):
            raise ValueError("Invalid account identifier")
        return self


class PasswordChange(StrictModel):
    current_password: Password
    new_password: Password


class Envelope(StrictModel):
    format_version: Literal[1] = 1
    envelope_revision: Revision
    key_version: Literal[1] = 1
    kdf_algorithm: Literal["PBKDF2-HMAC-SHA256"] = "PBKDF2-HMAC-SHA256"
    kdf_iterations: int = Field(ge=MIN_ITERATIONS, le=MAX_ITERATIONS)
    salt: Salt
    nonce: Nonce
    wrapped_key: WrappedKey


class VaultInit(StrictModel):
    id: ID
    envelope: Envelope


class VaultView(StrictModel):
    id: ID
    owner_id: ID
    envelope: Envelope


class EnvelopeUpdate(StrictModel):
    expected_revision: Revision
    envelope: Envelope


class RecordWrite(StrictModel):
    id: ID
    ciphertext: Ciphertext
    nonce: Nonce
    schema_version: Literal[1] = 1
    key_version: Literal[1] = 1
    revision: Revision


class RecordUpdate(StrictModel):
    expected_revision: Revision
    record: RecordWrite


class RecordView(RecordWrite):
    owner_id: ID
    vault_id: ID
    created_at: int
    updated_at: int


class PlainRecord(StrictModel):
    title: str = Field(min_length=1, max_length=256)
    username: str = Field(default="", max_length=1024)
    password: str = Field(default="", max_length=4096)
    url: str = Field(default="", max_length=2048)
    notes: str = Field(default="", max_length=16_384)
