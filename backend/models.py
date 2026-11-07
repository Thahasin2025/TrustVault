
from sqlalchemy import (
    Column, Integer, String, DateTime, Enum,
    Boolean, ForeignKey, JSON, UniqueConstraint
)
from sqlalchemy.sql import func
from backend.database import Base


# 1. Users table
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)

    role = Column(
        Enum("admin", "owner", "viewer", name="user_roles"),
        nullable=False,
        default="viewer"
    )
    is_active = Column(
        Boolean,
        nullable=False,
        default=True,
        server_default="1"
    )
    auth_version = Column(
        Integer,
        nullable=False,
        default=0,
        server_default="0"
    )

    created_at = Column(DateTime(timezone=True), server_default=func.now())


# 2. Documents table
class Document(Base):
    __tablename__ = "documents"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    storage_path = Column(String(500), nullable=False)
    category = Column(String(100), nullable=True)
    content_type = Column(String(100), nullable=False)
    file_size = Column(Integer, nullable=False)

    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now()
    )

    # Recycle Bin fields
    is_deleted = Column(
        Boolean,
        nullable=False,
        default=False,
        server_default="0"
    )

    deleted_at = Column(
        DateTime(timezone=True),
        nullable=True
    )

    purged_at = Column(
        DateTime(timezone=True),
        nullable=True
    )


# 3. Document permissions table
class DocumentPermission(Base):
    __tablename__ = "document_permissions"
    __table_args__ = (
        UniqueConstraint(
            "document_id",
            "user_id",
            name="uq_document_permission_user"
        ),
    )

    id = Column(Integer, primary_key=True, index=True)

    document_id = Column(
        Integer, ForeignKey("documents.id"), nullable=False
    )

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)

    can_read = Column(Boolean, default=True, nullable=False)
    can_edit = Column(Boolean, default=False, nullable=False)
    can_download = Column(Boolean, default=False, nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


# 4. Audit logs table
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)

    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=True)

    action = Column(String(100), nullable=False)
    details = Column(JSON, nullable=True)

    previous_hash = Column(String(64), nullable=True)
    current_hash = Column(String(64), nullable=False)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AuditVerification(Base):
    __tablename__ = "audit_verifications"

    id = Column(Integer, primary_key=True, default=1)
    verified_at = Column(DateTime(timezone=True), nullable=False)
    valid = Column(Boolean, nullable=False)
    checked_records = Column(Integer, nullable=False)
    valid_records = Column(Integer, nullable=False)
    invalid_records = Column(Integer, nullable=False)
    reason = Column(String(500), nullable=True)
    affected_record_id = Column(Integer, nullable=True)
    details = Column(JSON, nullable=True)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    token_hash = Column(String(64), primary_key=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


class LoginThrottle(Base):
    __tablename__ = "login_throttles"

    key_hash = Column(String(64), primary_key=True)
    window_started_at = Column(
        DateTime(timezone=False),
        nullable=False,
        index=True
    )
    attempt_count = Column(Integer, nullable=False)
