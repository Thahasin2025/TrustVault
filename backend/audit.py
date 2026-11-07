import hashlib
import hmac
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import event, text
from sqlalchemy.orm import Session as SQLAlchemySession

from backend.auth import SECRET_KEY
from backend import models

logger = logging.getLogger(__name__)

AUDIT_HMAC_KEY = (
    os.getenv("AUDIT_HMAC_KEY") or SECRET_KEY
).encode()
if len(AUDIT_HMAC_KEY) < 32:
    raise RuntimeError("AUDIT_HMAC_KEY must contain at least 32 bytes")
_configured_audit_verify_keys = tuple(
    key.strip().encode()
    for key in os.getenv("AUDIT_HMAC_VERIFY_KEYS", "").split(";")
    if key.strip()
)
_invalid_audit_verify_keys = tuple(
    key for key in _configured_audit_verify_keys if len(key) < 32
)
AUDIT_HMAC_VERIFY_KEYS = tuple(
    key for key in _configured_audit_verify_keys if len(key) >= 32
)
if _invalid_audit_verify_keys:
    logger.warning(
        "Ignoring %d AUDIT_HMAC_VERIFY_KEYS value(s) shorter than 32 bytes; "
        "records signed with those keys cannot be verified",
        len(_invalid_audit_verify_keys)
    )
AUDIT_LOCK_NAME = "trustvault_audit_chain"
AUDIT_ANCHOR_PATH = Path(
    os.getenv(
        "AUDIT_ANCHOR_PATH",
        str(Path(__file__).resolve().parent.parent / "uploads" / ".audit-anchor")
    )
)
_sqlite_audit_lock = threading.Lock()
_LOCK_INFO_KEY = "trustvault_audit_lock"
_PENDING_ANCHOR_KEY = "trustvault_pending_audit_anchor"
_APPEND_INFO_KEY = "trustvault_audit_append"


def _serialize_log(log: models.AuditLog) -> dict[str, Any]:
    return {
        "id": log.id,
        "actor_id": log.actor_id,
        "document_id": log.document_id,
        "action": log.action,
        "details": log.details,
        "created_at": str(log.created_at)
    }


def _legacy_hash(data: dict[str, Any]) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _signed_hash(data: dict[str, Any]) -> str:
    return _signed_hash_with_key(data, AUDIT_HMAC_KEY)


def _signed_hash_with_key(data: dict[str, Any], key: bytes) -> str:
    serialized = json.dumps(data, sort_keys=True, default=str)
    return hmac.new(
        key,
        serialized.encode(),
        hashlib.sha256
    ).hexdigest()


def _matches_signed_hash(data: dict[str, Any], digest: str) -> bool:
    return isinstance(digest, str) and any(
        hmac.compare_digest(digest, _signed_hash_with_key(data, key))
        for key in (AUDIT_HMAC_KEY, *AUDIT_HMAC_VERIFY_KEYS)
    )


def _record_id_ranges(record_ids: list[int]) -> list[dict[str, int]]:
    ranges: list[dict[str, int]] = []
    for record_id in record_ids:
        if ranges and record_id == ranges[-1]["last_id"] + 1:
            ranges[-1]["last_id"] = record_id
            ranges[-1]["count"] += 1
        else:
            ranges.append({
                "first_id": record_id,
                "last_id": record_id,
                "count": 1
            })
    return ranges


def create_hash(data: dict[str, Any]) -> str:
    """Create a keyed audit digest; legacy digests remain verifiable."""
    return _signed_hash(data)


def _acquire_audit_lock(db: SQLAlchemySession) -> None:
    if _LOCK_INFO_KEY in db.info:
        return

    dialect = db.get_bind().dialect.name
    if dialect == "mysql":
        raw_connection = db.connection().connection.driver_connection
        acquired = db.execute(
            text("SELECT GET_LOCK(:name, :timeout)"),
            {"name": AUDIT_LOCK_NAME, "timeout": 10}
        ).scalar()
        if acquired != 1:
            raise RuntimeError("Could not acquire the audit-chain lock")
        db.info[_LOCK_INFO_KEY] = ("mysql", raw_connection)
        return

    if not _sqlite_audit_lock.acquire(timeout=10):
        raise RuntimeError("Could not acquire the audit-chain lock")
    db.info[_LOCK_INFO_KEY] = ("thread", _sqlite_audit_lock)


def _release_audit_lock(db: SQLAlchemySession) -> None:
    lock = db.info.pop(_LOCK_INFO_KEY, None)
    if not lock:
        return

    lock_type, lock_object = lock
    if lock_type == "mysql":
        try:
            cursor = lock_object.cursor()
            try:
                cursor.execute(
                    "SELECT RELEASE_LOCK(%s)",
                    (AUDIT_LOCK_NAME,)
                )
            finally:
                cursor.close()
        except Exception:
            logger.exception("Could not release the audit-chain lock")
    elif lock_object:
        lock_object.release()


def _anchor_signature(anchor: dict[str, Any]) -> str:
    payload = json.dumps(anchor, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        AUDIT_HMAC_KEY,
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


def _write_anchor(log_id: int, current_hash: str) -> None:
    anchor = {"last_log_id": log_id, "current_hash": current_hash}
    payload = {
        **anchor,
        "signature": _anchor_signature(anchor)
    }
    AUDIT_ANCHOR_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=AUDIT_ANCHOR_PATH.parent,
            delete=False
        ) as anchor_file:
            json.dump(payload, anchor_file, sort_keys=True)
            anchor_file.flush()
            os.fsync(anchor_file.fileno())
            temporary_path = Path(anchor_file.name)
        os.replace(temporary_path, AUDIT_ANCHOR_PATH)
    except Exception:
        if temporary_path and temporary_path.exists():
            temporary_path.unlink()
        raise


def _read_anchor() -> dict[str, Any] | None:
    try:
        with AUDIT_ANCHOR_PATH.open(encoding="utf-8") as anchor_file:
            payload = json.load(anchor_file)
    except FileNotFoundError:
        return None

    if not isinstance(payload, dict):
        raise ValueError("The audit anchor has an invalid format")
    anchor = {
        "last_log_id": payload.get("last_log_id"),
        "current_hash": payload.get("current_hash")
    }
    signature = payload.get("signature")
    if (
        not isinstance(anchor["last_log_id"], int)
        or not isinstance(anchor["current_hash"], str)
        or not isinstance(signature, str)
        or not hmac.compare_digest(signature, _anchor_signature(anchor))
    ):
        raise ValueError("The audit anchor is invalid or has been modified")
    return anchor


@event.listens_for(SQLAlchemySession, "after_commit")
def _persist_pending_anchor(session: SQLAlchemySession) -> None:
    pending = session.info.pop(_PENDING_ANCHOR_KEY, None)
    if pending:
        try:
            _write_anchor(pending["last_log_id"], pending["current_hash"])
        except Exception:
            logger.exception(
                "Audit event committed, but its trusted anchor could not be updated"
            )
            session.info["trustvault_audit_anchor_error"] = True


@event.listens_for(SQLAlchemySession, "after_rollback")
def _discard_pending_anchor(session: SQLAlchemySession) -> None:
    session.info.pop(_PENDING_ANCHOR_KEY, None)


@event.listens_for(SQLAlchemySession, "after_transaction_end")
def _release_audit_lock_after_transaction(
    session: SQLAlchemySession,
    transaction: Any
) -> None:
    if transaction.parent is None:
        _release_audit_lock(session)
        session.info.pop(_PENDING_ANCHOR_KEY, None)


@event.listens_for(SQLAlchemySession, "before_flush")
def _prevent_audit_log_mutation(
    session: SQLAlchemySession,
    flush_context: Any,
    instances: Any
) -> None:
    if session.info.get(_APPEND_INFO_KEY):
        return
    if any(
        isinstance(entry, models.AuditLog)
        and entry not in session.new
        and session.is_modified(entry, include_collections=True)
        for entry in session.dirty
    ) or any(
        isinstance(entry, models.AuditLog)
        for entry in session.deleted
    ):
        raise ValueError("Audit records are append-only")


@event.listens_for(SQLAlchemySession, "do_orm_execute")
def _prevent_bulk_audit_log_mutation(execute_state: Any) -> None:
    if not (execute_state.is_update or execute_state.is_delete):
        return
    table = getattr(execute_state.statement, "table", None)
    if getattr(table, "name", None) == models.AuditLog.__tablename__:
        raise ValueError("Audit records are append-only")


def create_audit_log(
    db: SQLAlchemySession,
    actor_id: int | None,
    document_id: int | None,
    action: str,
    details: dict[str, Any] | None = None
) -> models.AuditLog:
    _acquire_audit_lock(db)

    previous_log = db.query(models.AuditLog).order_by(
        models.AuditLog.id.desc()
    ).with_for_update().first()
    previous_hash = previous_log.current_hash if previous_log else "GENESIS"

    event_details = dict(details or {})
    event_details.setdefault("outcome", "success")
    log_entry = models.AuditLog(
        actor_id=actor_id,
        document_id=document_id,
        action=action,
        details=event_details,
        previous_hash=previous_hash,
        current_hash="",
        created_at=datetime.now(timezone.utc).replace(
            tzinfo=None,
            microsecond=0
        )
    )
    db.info[_APPEND_INFO_KEY] = True
    try:
        db.add(log_entry)
        db.flush()

        log_data = _serialize_log(log_entry)
        log_entry.current_hash = _signed_hash({
            **log_data,
            "previous_hash": previous_hash
        })
        db.flush()
    finally:
        db.info.pop(_APPEND_INFO_KEY, None)
    db.info[_PENDING_ANCHOR_KEY] = {
        "last_log_id": log_entry.id,
        "current_hash": log_entry.current_hash
    }
    return log_entry


def verify_audit_chain(db: SQLAlchemySession) -> dict[str, Any]:
    logs = db.query(models.AuditLog).order_by(
        models.AuditLog.id.asc()
    ).all()
    expected_previous_hash = "GENESIS"
    invalid_records = 0
    invalid_record_ids = []
    current_key_chain_valid = []
    first_issue = None
    affected_record_id = None

    for log_entry in logs:
        log_data = _serialize_log(log_entry)
        hash_payload = {
            **log_data,
            "previous_hash": log_entry.previous_hash
        }
        expected_legacy_hash = _legacy_hash(hash_payload)

        record_valid = log_entry.previous_hash == expected_previous_hash
        current_key_valid = (
            record_valid
            and isinstance(log_entry.current_hash, str)
            and hmac.compare_digest(
                log_entry.current_hash,
                _signed_hash(hash_payload)
            )
        )
        hash_valid = (
            _matches_signed_hash(hash_payload, log_entry.current_hash)
            or (
                isinstance(log_entry.current_hash, str)
                and hmac.compare_digest(
                    log_entry.current_hash,
                    expected_legacy_hash
                )
            )
        )
        current_key_chain_valid.append(current_key_valid)
        if not record_valid or not hash_valid:
            invalid_records += 1
            invalid_record_ids.append(log_entry.id)
            if first_issue is None:
                affected_record_id = log_entry.id
                first_issue = (
                    f"Broken hash chain at audit log {log_entry.id}"
                    if not record_valid
                    else f"Invalid hash at audit log {log_entry.id}"
                )
        expected_previous_hash = log_entry.current_hash

    anchor = None
    try:
        anchor = _read_anchor()
    except (OSError, ValueError, json.JSONDecodeError) as error:
        if first_issue is None:
            first_issue = f"Audit anchor verification failed: {error}"
    if logs and anchor is None:
        if first_issue is None:
            first_issue = "Audit anchor is missing"
    if anchor and (
        not logs
        or anchor["last_log_id"] != logs[-1].id
        or anchor["current_hash"] != logs[-1].current_hash
    ):
        if first_issue is None:
            first_issue = "Audit database head does not match the trusted anchor"

    current_key_valid_suffix_count = 0
    for record_is_valid in reversed(current_key_chain_valid):
        if not record_is_valid:
            break
        current_key_valid_suffix_count += 1
    current_key_valid_suffix = {
        "count": current_key_valid_suffix_count,
        "first_id": (
            logs[-current_key_valid_suffix_count].id
            if current_key_valid_suffix_count
            else None
        ),
        "last_id": logs[-1].id if current_key_valid_suffix_count else None
    }

    checked_records = len(logs)
    return {
        "valid": first_issue is None,
        "reason": first_issue,
        "checked_logs": checked_records,
        "checked_records": checked_records,
        "valid_records": checked_records - invalid_records,
        "invalid_records": invalid_records,
        "affected_record_id": affected_record_id,
        "analysis": {
            "invalid_record_ranges": _record_id_ranges(invalid_record_ids),
            "current_key_valid_suffix": current_key_valid_suffix,
            "dedicated_key_configured": bool(os.getenv("AUDIT_HMAC_KEY"))
        }
    }


def initialize_audit_anchor(db: SQLAlchemySession) -> None:
    """Anchor a verified existing chain during an explicit migration."""
    result = verify_audit_chain(db)
    if not result["valid"]:
        if result["reason"] == "Audit anchor is missing" and result["checked_logs"]:
            logs = db.query(models.AuditLog).order_by(
                models.AuditLog.id.asc()
            ).all()
            expected_previous_hash = "GENESIS"
            for log_entry in logs:
                hash_payload = {
                    **_serialize_log(log_entry),
                    "previous_hash": log_entry.previous_hash
                }
                if log_entry.previous_hash != expected_previous_hash or not (
                    _matches_signed_hash(
                        hash_payload,
                        log_entry.current_hash
                    )
                    or hmac.compare_digest(
                        log_entry.current_hash,
                        _legacy_hash(hash_payload)
                    )
                ):
                    raise RuntimeError(
                        "Existing audit chain failed verification; anchor not created"
                    )
                expected_previous_hash = log_entry.current_hash
            _write_anchor(logs[-1].id, logs[-1].current_hash)
            return
        raise RuntimeError(result["reason"])

    if not result["checked_logs"]:
        return
