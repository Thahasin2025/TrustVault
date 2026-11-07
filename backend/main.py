
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from mimetypes import guess_type
from typing import Literal
from urllib.parse import quote

from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    UploadFile,
    File,
    Form
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field, model_validator
from sqlalchemy.orm import Session
from sqlalchemy.sql import func
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from backend import models
from backend.database import SessionLocal
from backend.auth import (
    hash_password,
    verify_password,
    create_access_token,
    verify_access_token,
    get_access_token_version,
    fingerprint_access_token,
    get_access_token_expiration
)
from backend.audit import create_audit_log, verify_audit_chain
from backend.login_throttle import (
    reserve_login_attempt,
    reset_account_ip_attempts
)


load_dotenv()

logger = logging.getLogger(__name__)

app = FastAPI(
    title="TrustVault",
    description="Secure Document Sharing with a Real Audit Trail",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

UPLOAD_DIR = Path(__file__).resolve().parent.parent / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_FILE_SIZE = 10 * 1024 * 1024
MAX_UPLOAD_REQUEST_SIZE = MAX_FILE_SIZE + 64 * 1024

ALLOWED_EXTENSIONS = {
    ".pdf",
    ".jpg",
    ".jpeg",
    ".png",
    ".txt"
}


class UploadRequestSizeLimitMiddleware:
    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send
    ) -> None:
        if (
            scope["type"] != "http"
            or scope.get("path") != "/documents/upload"
        ):
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                declared_length = int(content_length)
            except ValueError:
                declared_length = 0
            if declared_length > MAX_UPLOAD_REQUEST_SIZE:
                response = JSONResponse(
                    status_code=413,
                    content={"detail": "Upload request is too large"}
                )
                await response(scope, receive, send)
                return

        received_bytes = 0

        async def receive_with_limit() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > MAX_UPLOAD_REQUEST_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail="Upload request is too large"
                    )
            return message

        await self.app(scope, receive_with_limit, send)


app.add_middleware(UploadRequestSizeLimitMiddleware)


# ---------------- DATABASE ----------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------- COMMON HELPERS ----------------

def get_role_name(user):
    return (
        user.role.value
        if hasattr(user.role, "value")
        else user.role
    )


def get_private_file_path(document: models.Document) -> Path:
    file_path = Path(document.storage_path).resolve()
    try:
        file_path.relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        logger.error(
            "Stored path for document %s is outside private storage",
            document.id
        )
        raise HTTPException(
            status_code=500,
            detail="Stored document path is invalid"
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Stored document file not found"
        )
    return file_path


def has_document_permission(
    db: Session,
    document_id: int,
    current_user: models.User,
    permission_name: Literal["can_read", "can_download"]
) -> bool:
    if get_role_name(current_user) != "viewer":
        return False

    permission = db.query(models.DocumentPermission).filter(
        models.DocumentPermission.document_id == document_id,
        models.DocumentPermission.user_id == current_user.id,
        models.DocumentPermission.can_read.is_(True)
    ).first()
    if not permission:
        return False
    return bool(getattr(permission, permission_name))


def get_document_request_context(request: Request) -> tuple[int | None, str]:
    path_parts = request.url.path.strip("/").split("/")
    document_id = None
    if len(path_parts) > 1 and path_parts[0] == "documents":
        try:
            document_id = int(path_parts[1])
        except ValueError:
            pass

    if request.url.path == "/documents/upload":
        permission = "owner_upload"
    elif request.url.path.endswith("/download"):
        permission = "can_download"
    elif request.url.path.endswith("/view"):
        permission = "can_read"
    elif request.url.path.endswith("/purge"):
        permission = "owner_purge"
    elif "/share/" in request.url.path or request.url.path.endswith("/share"):
        permission = "manage_permissions"
    elif request.method == "PATCH":
        permission = "can_edit"
    elif request.method == "DELETE" or request.url.path.endswith("/restore"):
        permission = "owner_delete"
    elif request.url.path == "/documents/shared-with-me":
        permission = "can_read"
    elif request.url.path.endswith("/activity"):
        permission = "read_audit"
    else:
        permission = "list"

    return document_id, permission


@app.middleware("http")
async def audit_security_requests(request, call_next):
    is_login_request = request.url.path == "/login"
    is_document_request = (
        request.url.path == "/documents"
        or request.url.path.startswith("/documents/")
    )
    if not is_login_request and not is_document_request:
        return await call_next(request)

    actor_id = None
    authorization = request.headers.get("Authorization", "")
    if authorization.lower().startswith("bearer "):
        actor_id = verify_access_token(authorization[7:].strip())

    try:
        response = await call_next(request)
    except Exception:
        _record_security_request(request, actor_id, 500)
        raise

    if not _record_security_request(request, actor_id, response.status_code):
        return JSONResponse(
            status_code=503,
            content={
                "detail": (
                    "Audit recording failed. The operation may have completed; "
                    "verify its result before retrying."
                )
            }
        )
    return response


def _record_security_request(
    request: Request,
    actor_id: int | None,
    status_code: int
) -> bool:
    document_id, required_permission = get_document_request_context(request)
    is_login_request = request.url.path == "/login"
    if is_login_request:
        outcome = "success" if status_code < 400 else "failure"
    elif status_code in (401, 403, 404):
        outcome = "denied"
    elif status_code >= 400:
        outcome = "failure"
    else:
        outcome = "success"

    db = SessionLocal()
    try:
        create_audit_log(
            db,
            actor_id,
            document_id,
            "LOGIN_ATTEMPT" if is_login_request else "DOCUMENT_REQUEST",
            {
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "outcome": outcome,
                "required_permission": (
                    "authenticate" if is_login_request else required_permission
                ),
                "client_ip": request.client.host if request.client else None,
                "security_context": "direct_peer_only"
            }
        )
        db.commit()
        return True
    except Exception:
        db.rollback()
        logger.exception(
            "Failed to audit security request %s %s",
            request.method,
            request.url.path
        )
        return False
    finally:
        db.close()


# ---------------- AUTHENTICATION ----------------

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    user_id = verify_access_token(credentials.credentials)

    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token"
        )

    token_hash = fingerprint_access_token(credentials.credentials)
    if db.query(models.RevokedToken.token_hash).filter(
        models.RevokedToken.token_hash == token_hash
    ).first():
        raise HTTPException(
            status_code=401,
            detail="This access token has been revoked"
        )

    user = db.query(models.User).filter(
        models.User.id == user_id
    ).first()

    if not user:
        raise HTTPException(
            status_code=401,
            detail="User not found"
        )

    if not user.is_active:
        raise HTTPException(
            status_code=403,
            detail="This account is suspended"
        )

    token_version = get_access_token_version(credentials.credentials)
    if token_version is None or token_version != user.auth_version:
        raise HTTPException(
            status_code=401,
            detail="This access token is no longer valid"
        )

    return user


def require_role(required_role):

    def role_checker(
        current_user: models.User = Depends(get_current_user)
    ):
        if get_role_name(current_user) != required_role:
            raise HTTPException(
                status_code=403,
                detail="You do not have permission to perform this action"
            )

        return current_user

    return role_checker


# ---------------- REQUEST MODELS ----------------

class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8)
    role: Literal["owner", "viewer"] = "viewer"


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ShareDocumentRequest(BaseModel):
    viewer_user_id: int
    can_read: bool = True
    can_edit: bool = False
    can_download: bool = False


class UpdateDocumentRequest(BaseModel):
    filename: str | None = Field(default=None, min_length=1, max_length=255)
    category: str | None = Field(default=None, min_length=1, max_length=50)


class AdminUserUpdateRequest(BaseModel):
    role: Literal["admin", "owner", "viewer"] | None = None
    is_active: bool | None = None

    @model_validator(mode="after")
    def require_update(self):
        if self.role is None and self.is_active is None:
            raise ValueError("Provide a role or account status to update")
        return self


# ---------------- REGISTER ----------------

@app.post("/register")
def register_user(
    request: RegisterRequest,
    db: Session = Depends(get_db)
):
    existing_user = db.query(models.User).filter(
        models.User.email == str(request.email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Email already registered"
        )

    new_user = models.User(
        full_name=request.full_name.strip(),
        email=str(request.email),
        hashed_password=hash_password(request.password),
        role=request.role
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "Registration successful",
        "user_id": new_user.id,
        "full_name": new_user.full_name,
        "email": new_user.email,
        "role": get_role_name(new_user)
    }


# ---------------- LOGIN ----------------

@app.post("/login")
def login_user(
    request: LoginRequest,
    http_request: Request,
    db: Session = Depends(get_db)
):
    client_ip = http_request.client.host if http_request.client else "unknown"
    retry_after = reserve_login_attempt(
        db,
        str(request.email),
        client_ip
    )
    if retry_after is not None:
        raise HTTPException(
            status_code=429,
            detail=(
                "Too many failed login attempts. "
                f"Try again in {retry_after} seconds."
            ),
            headers={"Retry-After": str(retry_after)}
        )

    user = db.query(models.User).filter(
        models.User.email == str(request.email)
    ).first()

    if not user or not verify_password(
        request.password,
        user.hashed_password
    ):
        try:
            create_audit_log(
                db,
                user.id if user else None,
                None,
                "USER_LOGIN_FAILED",
                {
                    "outcome": "failure",
                    "client_ip": (
                        http_request.client.host if http_request.client else None
                    ),
                    "security_context": "invalid_credentials"
                }
            )
            db.commit()
        except Exception as error:
            db.rollback()
            logger.exception("Could not record failed login")
            raise HTTPException(
                status_code=500,
                detail="Login could not be completed because activity logging failed"
            ) from error
        raise HTTPException(
            status_code=401,
            detail="Incorrect email or password"
        )

    if not user.is_active:
        try:
            create_audit_log(
                db,
                user.id,
                None,
                "USER_LOGIN_FAILED",
                {
                    "outcome": "failure",
                    "client_ip": (
                        http_request.client.host if http_request.client else None
                    ),
                    "security_context": "inactive_account"
                }
            )
            db.commit()
        except Exception as error:
            db.rollback()
            logger.exception(
                "Could not record failed login for inactive user %s",
                user.id
            )
            raise HTTPException(
                status_code=500,
                detail="Login could not be completed because activity logging failed"
            ) from error
        raise HTTPException(
            status_code=403,
            detail="This account is suspended"
        )

    try:
        reset_account_ip_attempts(
            db,
            str(request.email),
            client_ip
        )
        create_audit_log(
            db,
            user.id,
            None,
            "USER_LOGGED_IN",
            {
                "full_name": user.full_name,
                "email": user.email,
                "outcome": "success",
                "client_ip": (
                    http_request.client.host if http_request.client else None
                ),
                "security_context": "password_authentication"
            }
        )
        db.commit()
    except Exception as error:
        db.rollback()
        logger.exception("Could not record successful login for user %s", user.id)
        raise HTTPException(
            status_code=500,
            detail="Login could not be completed because activity logging failed"
        ) from error

    return {
        "message": "Login successful",
        "access_token": create_access_token(user.id, user.auth_version),
        "token_type": "bearer",
        "user_id": user.id,
        "role": get_role_name(user)
    }


# ---------------- CURRENT USER ----------------

@app.get("/me")
def get_my_profile(
    current_user: models.User = Depends(get_current_user)
):
    return {
        "user_id": current_user.id,
        "full_name": current_user.full_name,
        "email": current_user.email,
        "role": get_role_name(current_user)
    }


@app.post("/logout")
def logout_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    token_expiration = get_access_token_expiration(
        credentials.credentials
    )
    if token_expiration is None:
        raise HTTPException(status_code=401, detail="Invalid access token")

    token_hash = fingerprint_access_token(credentials.credentials)
    db.add(models.RevokedToken(
        token_hash=token_hash,
        expires_at=token_expiration
    ))
    db.query(models.RevokedToken).filter(
        models.RevokedToken.expires_at <= datetime.now(timezone.utc)
    ).delete(synchronize_session=False)

    try:
        create_audit_log(
            db,
            current_user.id,
            None,
            "USER_LOGGED_OUT",
            {}
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not revoke access token during logout")
        raise HTTPException(
            status_code=500,
            detail="Logout could not be completed"
        )

    return {"message": "Logged out successfully"}


@app.get("/users/viewers")
def get_viewers(
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):
    viewers = db.query(models.User).filter(
        models.User.role == "viewer",
        models.User.is_active.is_(True)
    ).order_by(
        models.User.full_name.asc(),
        models.User.id.asc()
    ).all()

    return {
        "viewers": [
            {
                "user_id": viewer.id,
                "full_name": viewer.full_name,
                "email": viewer.email
            }
            for viewer in viewers
        ]
    }


# ---------------- ADMIN DASHBOARD ----------------

@app.get("/admin/dashboard")
def admin_dashboard(
    current_user: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    return {
        "message": "Welcome to the Admin Dashboard",
        "total_users": db.query(models.User).count(),
        "total_documents": db.query(models.Document).count()
    }


# ---------------- ADMIN AUDIT LOGS ----------------

@app.get("/admin/audit-logs")
def get_audit_logs(
    current_user: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    logs = db.query(models.AuditLog).order_by(
        models.AuditLog.id.desc()
    ).limit(500).all()
    actor_ids = {
        log.actor_id for log in logs if log.actor_id is not None
    }
    users_by_id = {}
    if actor_ids:
        users_by_id = {
            user.id: user
            for user in db.query(models.User).filter(
                models.User.id.in_(actor_ids)
            ).all()
        }
    audit_log_rows = []
    for log in logs:
        details = log.details if isinstance(log.details, dict) else {}
        actor = users_by_id.get(log.actor_id)
        created_at = (
            log.created_at.replace(tzinfo=timezone.utc)
            if log.created_at.tzinfo is None
            else log.created_at
        )
        audit_log_rows.append({
            "id": log.id,
            "actor_id": log.actor_id,
            "document_id": log.document_id,
            "action": log.action,
            "details": log.details,
            "actor_name": actor.full_name if actor else details.get("full_name"),
            "actor_role": get_role_name(actor) if actor else None,
            "previous_hash": log.previous_hash,
            "current_hash": log.current_hash,
            "created_at": created_at.isoformat()
        })

    return {
        "total_returned": len(logs),
        "audit_logs": audit_log_rows
    }


# ---------------- VERIFY AUDIT CHAIN ----------------

@app.get("/admin/audit-logs/verify")
def verify_audit_logs(
    current_user: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    result = verify_audit_chain(db)
    verified_at = datetime.now(timezone.utc).replace(microsecond=0)
    verification = db.query(models.AuditVerification).filter(
        models.AuditVerification.id == 1
    ).first()
    if verification is None:
        verification = models.AuditVerification(id=1)
        db.add(verification)

    verification.verified_at = verified_at
    verification.valid = result["valid"]
    verification.checked_records = result["checked_records"]
    verification.valid_records = result["valid_records"]
    verification.invalid_records = result["invalid_records"]
    verification.reason = result["reason"]
    verification.affected_record_id = result["affected_record_id"]
    verification.details = result["analysis"]
    db.commit()
    return {
        **result,
        "verified_at": verified_at.isoformat()
    }


@app.get("/admin/audit-logs/verification")
def get_last_audit_verification(
    current_user: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    verification = db.query(models.AuditVerification).filter(
        models.AuditVerification.id == 1
    ).first()
    if verification is None:
        return {"verification": None}

    verified_at = verification.verified_at
    if verified_at.tzinfo is None:
        verified_at = verified_at.replace(tzinfo=timezone.utc)
    return {
        "verification": {
            "verified_at": verified_at.isoformat(),
            "valid": verification.valid,
            "checked_records": verification.checked_records,
            "valid_records": verification.valid_records,
            "invalid_records": verification.invalid_records,
            "reason": verification.reason,
            "affected_record_id": verification.affected_record_id,
            "analysis": verification.details
        }
    }


@app.get("/admin/users")
def get_admin_users(
    current_user: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    users = db.query(models.User).order_by(
        models.User.id.asc()
    ).all()

    return {
        "users": [
            {
                "user_id": user.id,
                "full_name": user.full_name,
                "email": user.email,
                "role": get_role_name(user),
                "is_active": user.is_active,
                "created_at": user.created_at
            }
            for user in users
        ]
    }


@app.patch("/admin/users/{user_id}")
def update_admin_user(
    user_id: int,
    request: AdminUserUpdateRequest,
    current_user: models.User = Depends(require_role("admin")),
    db: Session = Depends(get_db)
):
    if user_id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot change your own role or account status"
        )

    active_admins = db.query(models.User).filter(
        models.User.role == "admin",
        models.User.is_active.is_(True)
    ).order_by(
        models.User.id.asc()
    ).with_for_update().all()

    user = db.query(models.User).filter(
        models.User.id == user_id
    ).with_for_update().first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    previous_role = get_role_name(user)
    previous_active = user.is_active
    next_role = request.role or previous_role
    next_active = (
        request.is_active
        if request.is_active is not None
        else previous_active
    )

    if previous_role == "owner" and next_role != "owner":
        owned_documents = db.query(models.Document.id).filter(
            models.Document.owner_id == user_id
        ).first()
        if owned_documents:
            raise HTTPException(
                status_code=409,
                detail="Transfer or delete this user's documents before changing the role"
            )

    if previous_role == "admin" and (
        next_role != "admin" or not next_active
    ):
        remaining_active_admins = [
            admin
            for admin in active_admins
            if admin.id != user_id
        ]
        if not remaining_active_admins:
            raise HTTPException(
                status_code=409,
                detail="At least one active administrator must remain"
            )

    user.role = next_role
    user.is_active = next_active

    try:
        create_audit_log(
            db,
            current_user.id,
            None,
            "ADMIN_USER_UPDATED",
            {
                "target_user_id": user.id,
                "previous_role": previous_role,
                "role": next_role,
                "previous_is_active": previous_active,
                "is_active": next_active
            }
        )
        db.commit()
        db.refresh(user)
    except Exception:
        db.rollback()
        logger.exception("Admin user update failed for user %s", user_id)
        raise HTTPException(
            status_code=500,
            detail="User update failed"
        )

    return {
        "user_id": user.id,
        "role": get_role_name(user),
        "is_active": user.is_active
    }


# ---------------- FILE VALIDATION ----------------

def validate_file_content(extension: str, content: bytes) -> bool:
    return detect_file_content_type(extension, content) is not None


def detect_file_content_type(extension: str, content: bytes) -> str | None:
    if extension == ".pdf":
        return "application/pdf" if content.startswith(b"%PDF-") else None

    if extension == ".png":
        return (
            "image/png"
            if content.startswith(b"\x89PNG\r\n\x1a\n")
            else None
        )

    if extension in [".jpg", ".jpeg"]:
        return (
            "image/jpeg"
            if content.startswith(b"\xff\xd8\xff")
            else None
        )

    if extension == ".txt":
        try:
            text_content = content.decode("utf-8")
            if "\x00" not in text_content:
                return "text/plain"
        except UnicodeDecodeError:
            return None

    return None


# ---------------- DOCUMENT UPLOAD ----------------

@app.post("/documents/upload")
async def upload_document(
    file: UploadFile = File(...),
    category: str = Form(...),
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    filename = Path((file.filename or "").replace("\\", "/")).name
    extension = Path(filename).suffix.lower()

    if not filename:
        raise HTTPException(
            status_code=400,
            detail="Filename is required"
        )
    if len(filename) > 255 or any(
        ord(character) < 32 or ord(character) == 127
        for character in filename
    ):
        raise HTTPException(status_code=400, detail="Invalid filename")

    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="File type not allowed"
        )

    if not category.strip() or len(category.strip()) > 50:
        raise HTTPException(
            status_code=400,
            detail="Invalid category"
        )

    content = await file.read(MAX_FILE_SIZE + 1)

    if not content:
        raise HTTPException(
            status_code=400,
            detail="Empty files are not allowed"
        )

    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail="File size exceeds 10 MB"
        )

    detected_content_type = detect_file_content_type(extension, content)
    if not detected_content_type:
        raise HTTPException(
            status_code=400,
            detail="File content does not match its extension"
        )

    declared_content_type = (file.content_type or "").split(";", 1)[0].strip().lower()
    if declared_content_type not in (
        "",
        "application/octet-stream",
        detected_content_type
    ):
        raise HTTPException(
            status_code=400,
            detail="Declared MIME type does not match file content"
        )

    stored_path = UPLOAD_DIR / (
        str(uuid.uuid4()) + extension
    )

    try:
        stored_path.write_bytes(content)

        document = models.Document(
            filename=filename,
            storage_path=str(stored_path),
            category=category.strip(),
            content_type=detected_content_type,
            file_size=len(content),
            owner_id=current_user.id
        )

        db.add(document)
        db.flush()

        create_audit_log(
            db,
            current_user.id,
            document.id,
            "DOCUMENT_UPLOADED",
            {
                "filename": filename,
                "category": category.strip(),
                "file_size": len(content)
            }
        )

        db.commit()
        db.refresh(document)

        return {
            "message": "Document uploaded successfully",
            "document_id": document.id,
            "filename": document.filename,
            "category": document.category,
            "file_size": document.file_size,
            "owner_id": document.owner_id
        }

    except Exception:
        db.rollback()

        if stored_path.exists():
            stored_path.unlink()

        raise HTTPException(
            status_code=500,
            detail="Document upload failed"
        )

    finally:
        await file.close()


# ---------------- OWNER DOCUMENT LIST ----------------

@app.get("/documents/mine")
def get_my_documents(
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    documents = db.query(models.Document).filter(
        models.Document.owner_id == current_user.id,
        models.Document.is_deleted.is_(False)
    ).order_by(
        models.Document.created_at.desc()
    ).all()

    permissions_by_document = {}

    if documents:
        permissions = db.query(
            models.DocumentPermission,
            models.User
        ).join(
            models.User,
            models.DocumentPermission.user_id == models.User.id
        ).filter(
            models.DocumentPermission.document_id.in_(
                [document.id for document in documents]
            )
        ).all()

        for permission, viewer in permissions:
            permissions_by_document.setdefault(
                permission.document_id,
                []
            ).append({
                "user_id": viewer.id,
                "full_name": viewer.full_name,
                "email": viewer.email,
                "can_read": permission.can_read,
                "can_edit": permission.can_edit,
                "can_download": permission.can_download
            })

    return {
        "message": "Your documents retrieved successfully",
        "total_documents": len(documents),
        "documents": [
            {
                "document_id": doc.id,
                "filename": doc.filename,
                "category": doc.category,
                "content_type": doc.content_type,
                "file_size": doc.file_size,
                "owner_id": doc.owner_id,
                "owner_name": current_user.full_name,
                "owner_email": current_user.email,
                "created_at": doc.created_at,
                "permissions": permissions_by_document.get(doc.id, [])
            }
            for doc in documents
        ]
    }


# ---------------- VIEWER: SHARED WITH ME ----------------

@app.get("/documents/shared-with-me")
def get_shared_documents(
    current_user: models.User = Depends(require_role("viewer")),
    db: Session = Depends(get_db)
):
    shared_documents = db.query(
        models.Document,
        models.DocumentPermission,
        models.User
    ).join(
        models.DocumentPermission,
        models.Document.id == models.DocumentPermission.document_id
    ).join(
        models.User,
        models.Document.owner_id == models.User.id
    ).filter(
        models.DocumentPermission.user_id == current_user.id,
        models.DocumentPermission.can_read.is_(True),
        models.Document.is_deleted.is_(False)
    ).order_by(
        models.Document.created_at.desc()
    ).all()

    return {
        "message": "Shared documents retrieved successfully",
        "total_documents": len(shared_documents),
        "documents": [
            {
                "document_id": doc.id,
                "filename": doc.filename,
                "category": doc.category,
                "content_type": doc.content_type,
                "file_size": doc.file_size,
                "owner_id": doc.owner_id,
                "created_at": doc.created_at,
                "can_read": permission.can_read,
                "can_edit": permission.can_edit,
                "can_download": permission.can_download,
                "owner_name": owner.full_name,
                "owner_email": owner.email
            }
            for doc, permission, owner in shared_documents
        ]
    }


@app.patch("/documents/{document_id}")
def update_document_metadata(
    document_id: int,
    request: UpdateDocumentRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not request.model_fields_set:
        raise HTTPException(
            status_code=422,
            detail="Provide a filename or category to update"
        )

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.is_deleted.is_(False)
    ).first()

    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    is_owner = document.owner_id == current_user.id
    edit_permission = None
    if not is_owner:
        edit_permission = db.query(models.DocumentPermission).filter(
            models.DocumentPermission.document_id == document_id,
            models.DocumentPermission.user_id == current_user.id,
            models.DocumentPermission.can_read.is_(True),
            models.DocumentPermission.can_edit.is_(True)
        ).first()

    if (
        not is_owner
        and (
            get_role_name(current_user) != "viewer"
            or not edit_permission
        )
    ):
        raise HTTPException(
            status_code=403,
            detail="You do not have edit permission for this document"
        )

    previous_values = {
        "filename": document.filename,
        "category": document.category
    }

    if "filename" in request.model_fields_set:
        filename = Path(request.filename or "").name.strip()
        if (
            not filename
            or Path(filename).suffix.lower()
            != Path(document.filename).suffix.lower()
        ):
            raise HTTPException(
                status_code=400,
                detail="Filename must keep the original file extension"
            )
        document.filename = filename

    if "category" in request.model_fields_set:
        category = (request.category or "").strip()
        if not category or len(category) > 50:
            raise HTTPException(status_code=400, detail="Invalid category")
        document.category = category

    try:
        create_audit_log(
            db,
            current_user.id,
            document.id,
            "DOCUMENT_METADATA_UPDATED",
            {
                "before": previous_values,
                "after": {
                    "filename": document.filename,
                    "category": document.category
                }
            }
        )
        db.commit()
        db.refresh(document)
    except Exception:
        db.rollback()
        logger.exception("Document metadata update failed")
        raise HTTPException(
            status_code=500,
            detail="Document metadata update failed"
        )

    return {
        "document_id": document.id,
        "filename": document.filename,
        "category": document.category,
        "updated_at": document.updated_at
    }


@app.get("/documents/{document_id}/activity")
def get_document_activity(
    document_id: int,
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):
    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == current_user.id
    ).first()
    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or you are not the owner"
        )

    logs = db.query(models.AuditLog).filter(
        models.AuditLog.document_id == document_id
    ).order_by(
        models.AuditLog.id.desc()
    ).limit(200).all()

    try:
        create_audit_log(
            db,
            current_user.id,
            document_id,
            "DOCUMENT_ACTIVITY_VIEWED",
            {}
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Document activity audit failed")
        raise HTTPException(
            status_code=500,
            detail="Document activity could not be loaded"
        )

    return {
        "document_id": document_id,
        "activity": [
            {
                "id": log.id,
                "actor_id": log.actor_id,
                "action": log.action,
                "details": log.details,
                "created_at": log.created_at
            }
            for log in logs
        ]
    }


# ---------------- RECYCLE BIN LIST ----------------

@app.get("/documents/recycle-bin")
def get_recycle_bin(
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    documents = db.query(models.Document).filter(
        models.Document.owner_id == current_user.id,
        models.Document.is_deleted.is_(True)
    ).order_by(
        models.Document.deleted_at.desc()
    ).all()

    return {
        "message": "Recycle Bin documents retrieved successfully",
        "total_documents": len(documents),
        "documents": [
            {
                "document_id": doc.id,
                "filename": doc.filename,
                "category": doc.category,
                "content_type": doc.content_type,
                "file_size": doc.file_size,
                "owner_id": doc.owner_id,
                "created_at": doc.created_at,
                "deleted_at": doc.deleted_at,
                "is_deleted": doc.is_deleted,
                "purged_at": doc.purged_at
            }
            for doc in documents
        ]
    }


# ---------------- RESTORE DOCUMENT FROM RECYCLE BIN ----------------

@app.post("/documents/{document_id}/restore")
def restore_document(
    document_id: int,
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == current_user.id,
        models.Document.is_deleted.is_(True),
        models.Document.purged_at.is_(None)
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Deleted document not found or you are not the owner"
        )

    try:
        document.is_deleted = False
        document.deleted_at = None

        create_audit_log(
            db,
            current_user.id,
            document.id,
            "DOCUMENT_RESTORED",
            {
                "filename": document.filename,
                "owner_id": current_user.id
            }
        )

        db.commit()
        db.refresh(document)

        return {
            "message": "Document restored successfully",
            "document_id": document.id,
            "filename": document.filename,
            "is_deleted": document.is_deleted,
            "deleted_at": document.deleted_at
        }

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to restore document"
        )


@app.post("/documents/{document_id}/purge")
def purge_document(
    document_id: int,
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):
    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == current_user.id,
        models.Document.is_deleted.is_(True),
        models.Document.purged_at.is_(None)
    ).first()
    if not document:
        raise HTTPException(
            status_code=404,
            detail="Deleted document not found or already purged"
        )

    file_path = Path(os.path.abspath(document.storage_path))
    try:
        file_path.relative_to(UPLOAD_DIR.resolve())
    except ValueError:
        logger.error(
            "Stored path for document %s is outside private storage",
            document.id
        )
        raise HTTPException(
            status_code=500,
            detail="Stored document path is invalid"
        )

    if file_path.is_symlink():
        logger.error(
            "Stored path for document %s is a symbolic link",
            document.id
        )
        raise HTTPException(
            status_code=500,
            detail="Stored document path is invalid"
        )

    if file_path.exists():
        if not file_path.is_file():
            raise HTTPException(
                status_code=500,
                detail="Stored document file is not a regular file"
            )
        try:
            file_path.unlink()
        except OSError:
            logger.exception(
                "Could not remove private file for document %s",
                document.id
            )
            raise HTTPException(
                status_code=500,
                detail="Document file could not be removed"
            )

    purged_at = datetime.now(timezone.utc).replace(tzinfo=None)
    try:
        document.storage_path = ""
        document.purged_at = purged_at
        create_audit_log(
            db,
            current_user.id,
            document.id,
            "DOCUMENT_FILE_PURGED",
            {
                "filename": document.filename,
                "active_storage_file_removed": True,
                "metadata_retained": True
            }
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Document purge record failed for %s", document_id)
        raise HTTPException(
            status_code=500,
            detail=(
                "File removal may have completed, but its audit record "
                "could not be committed. Check the recycle bin before retrying."
            )
        )

    return {
        "message": "Document file removed from private storage",
        "document_id": document.id,
        "purged_at": purged_at,
        "metadata_retained": True
    }


# ---------------- MOVE DOCUMENT TO RECYCLE BIN ----------------

@app.delete("/documents/{document_id}")
def delete_document(
    document_id: int,
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == current_user.id,
        models.Document.is_deleted.is_(False)
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or already deleted"
        )

    try:
        document.is_deleted = True
        document.deleted_at = func.now()

        create_audit_log(
            db,
            current_user.id,
            document.id,
            "DOCUMENT_MOVED_TO_RECYCLE_BIN",
            {
                "filename": document.filename,
                "owner_id": current_user.id
            }
        )

        db.commit()
        db.refresh(document)

        return {
            "message": "Document moved to Recycle Bin successfully",
            "document_id": document.id,
            "filename": document.filename,
            "is_deleted": document.is_deleted,
            "deleted_at": document.deleted_at
        }

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Failed to move document to Recycle Bin"
        )


# ---------------- SHARE DOCUMENT ----------------

@app.post("/documents/{document_id}/share")
def share_document(
    document_id: int,
    request: ShareDocumentRequest,
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == current_user.id,
        models.Document.is_deleted.is_(False)
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or you are not the owner"
        )

    viewer = db.query(models.User).filter(
        models.User.id == request.viewer_user_id
    ).first()

    if not viewer:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    if not viewer.is_active:
        raise HTTPException(
            status_code=400,
            detail="Suspended users cannot be granted document access"
        )

    if viewer.id == current_user.id:
        raise HTTPException(
            status_code=400,
            detail="You cannot share a document with yourself"
        )

    if get_role_name(viewer) != "viewer":
        raise HTTPException(
            status_code=400,
            detail="Document can only be shared with a Viewer account"
        )

    if not request.can_read:
        raise HTTPException(
            status_code=400,
            detail="Read permission is required; revoke access to remove it"
        )

    permission = db.query(
        models.DocumentPermission
    ).filter(
        models.DocumentPermission.document_id == document_id,
        models.DocumentPermission.user_id == viewer.id
    ).first()

    previous_permission = None

    if permission:
        previous_permission = {
            "can_read": permission.can_read,
            "can_edit": permission.can_edit,
            "can_download": permission.can_download
        }

        permission.can_read = request.can_read
        permission.can_edit = request.can_edit
        permission.can_download = request.can_download
        permission.granted_by = current_user.id

    else:
        permission = models.DocumentPermission(
            document_id=document_id,
            user_id=viewer.id,
            granted_by=current_user.id,
            can_read=request.can_read,
            can_edit=request.can_edit,
            can_download=request.can_download
        )

        db.add(permission)

    try:
        create_audit_log(
            db,
            current_user.id,
            document_id,
            "PERMISSION_GRANTED_OR_UPDATED",
            {
                "viewer_user_id": viewer.id,
                "can_read": request.can_read,
                "can_edit": request.can_edit,
                "can_download": request.can_download,
                "previous_permission": previous_permission
            }
        )

        db.commit()
        db.refresh(permission)

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Sharing document failed"
        )

    return {
        "message": "Document shared successfully",
        "document_id": document_id,
        "viewer_user_id": viewer.id,
        "can_read": permission.can_read,
        "can_edit": permission.can_edit,
        "can_download": permission.can_download
    }


# ---------------- REVOKE DOCUMENT PERMISSION ----------------

@app.delete("/documents/{document_id}/share/{viewer_user_id}")
def revoke_document_permission(
    document_id: int,
    viewer_user_id: int,
    current_user: models.User = Depends(require_role("owner")),
    db: Session = Depends(get_db)
):

    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.owner_id == current_user.id
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found or you are not the owner"
        )

    permission = db.query(
        models.DocumentPermission
    ).filter(
        models.DocumentPermission.document_id == document_id,
        models.DocumentPermission.user_id == viewer_user_id
    ).first()

    if not permission:
        raise HTTPException(
            status_code=404,
            detail="No permission found for this Viewer"
        )

    revoked_permission = {
        "viewer_user_id": viewer_user_id,
        "can_read": permission.can_read,
        "can_edit": permission.can_edit,
        "can_download": permission.can_download
    }

    try:
        db.delete(permission)

        create_audit_log(
            db,
            current_user.id,
            document_id,
            "PERMISSION_REVOKED",
            revoked_permission
        )

        db.commit()

    except Exception:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Revoking document access failed"
        )

    return {
        "message": "Document access revoked successfully",
        "document_id": document_id,
        "viewer_user_id": viewer_user_id
    }


# ---------------- SECURE DOCUMENT VIEW ----------------

@app.get("/documents/{document_id}/view")
def view_document(
    document_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.is_deleted.is_(False)
    ).first()

    if not document:
        raise HTTPException(
            status_code=404,
            detail="Document not found"
        )

    is_owner = document.owner_id == current_user.id
    if not is_owner and not has_document_permission(
        db, document_id, current_user, "can_read"
    ):
        raise HTTPException(
            status_code=403,
            detail="You do not have read permission for this document"
        )

    file_path = get_private_file_path(document)

    try:
        create_audit_log(
            db,
            current_user.id,
            document_id,
            "DOCUMENT_VIEWED",
            {
                "filename": document.filename,
                "was_owner": is_owner
            }
        )

        db.commit()

    except Exception:
        db.rollback()
        logger.exception("Document view audit failed")
        raise HTTPException(
            status_code=500,
            detail="Document view could not be completed because audit logging failed"
        )

    media_type, _ = guess_type(document.filename)
    if not media_type:
        media_type = document.content_type or "application/octet-stream"

    safe_filename = quote(document.filename)
    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f"inline; filename*=UTF-8''{safe_filename}"
            ),
            "X-Content-Type-Options": "nosniff"
        }
    )


# ---------------- SECURE DOCUMENT DOWNLOAD ----------------

@app.get("/documents/{document_id}/download")
def download_document(
    document_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    document = db.query(models.Document).filter(
        models.Document.id == document_id,
        models.Document.is_deleted.is_(False)
    ).first()

    if not document:
        raise HTTPException(status_code=404, detail="Document not found")

    is_owner = document.owner_id == current_user.id
    if not is_owner and not has_document_permission(
        db, document_id, current_user, "can_download"
    ):
        raise HTTPException(
            status_code=403,
            detail="You do not have download permission for this document"
        )

    file_path = get_private_file_path(document)
    try:
        create_audit_log(
            db,
            current_user.id,
            document_id,
            "DOCUMENT_DOWNLOADED",
            {"filename": document.filename, "was_owner": is_owner}
        )
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Document download audit failed")
        raise HTTPException(
            status_code=500,
            detail="Download could not be completed because audit logging failed"
        )

    media_type, _ = guess_type(document.filename)
    if not media_type:
        media_type = document.content_type or "application/octet-stream"

    return FileResponse(
        path=str(file_path),
        media_type=media_type,
        headers={
            "Content-Disposition": (
                f"attachment; filename*=UTF-8''{quote(document.filename)}"
            ),
            "X-Content-Type-Options": "nosniff"
        }
    )


FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
app.mount(
    "/",
    StaticFiles(directory=str(FRONTEND_DIR), html=True),
    name="frontend"
)
