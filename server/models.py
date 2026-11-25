from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    ForeignKeyConstraint,
    Integer,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    password_algorithm: Mapped[str] = mapped_column(String(32))
    password_salt: Mapped[bytes] = mapped_column(LargeBinary(16))
    password_iterations: Mapped[int] = mapped_column(Integer)
    password_verifier: Mapped[bytes] = mapped_column(LargeBinary(32))
    auth_version: Mapped[int] = mapped_column(Integer, default=1)
    __table_args__ = (CheckConstraint("password_iterations >= 600000 AND password_iterations <= 2000000"),)


class Session(Base):
    __tablename__ = "sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[int] = mapped_column(Integer, index=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    auth_version: Mapped[int] = mapped_column(Integer)


class Vault(Base):
    __tablename__ = "vaults"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("users.id"), unique=True)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary(48))
    salt: Mapped[bytes] = mapped_column(LargeBinary(16))
    kdf_algorithm: Mapped[str] = mapped_column(String(32))
    kdf_iterations: Mapped[int] = mapped_column(Integer)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12))
    format_version: Mapped[int] = mapped_column(Integer)
    envelope_revision: Mapped[int] = mapped_column(Integer)
    key_version: Mapped[int] = mapped_column(Integer)
    __table_args__ = (
        UniqueConstraint("id", "owner_id"),
        CheckConstraint("envelope_revision >= 1"),
        CheckConstraint("kdf_iterations >= 600000 AND kdf_iterations <= 2000000"),
    )


class Record(Base):
    __tablename__ = "records"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    owner_id: Mapped[str] = mapped_column(String(36), index=True)
    vault_id: Mapped[str] = mapped_column(String(36), index=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    nonce: Mapped[bytes] = mapped_column(LargeBinary(12))
    schema_version: Mapped[int] = mapped_column(Integer)
    key_version: Mapped[int] = mapped_column(Integer)
    revision: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[int] = mapped_column(Integer)
    updated_at: Mapped[int] = mapped_column(Integer)
    deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    __table_args__ = (
        ForeignKeyConstraint(["vault_id", "owner_id"], ["vaults.id", "vaults.owner_id"]),
        CheckConstraint("revision >= 1"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(40))
    actor_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    result: Mapped[str] = mapped_column(String(24))
    time: Mapped[int] = mapped_column(Integer, index=True)
