import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from sqlalchemy import case
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from backend.auth import SECRET_KEY
from backend.models import LoginThrottle

LOGIN_ATTEMPT_WINDOW = timedelta(minutes=15)
MAX_FAILURES_PER_IP = 20
MAX_FAILURES_PER_ACCOUNT_AND_IP = 5


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _bucket_hash(value: str) -> str:
    return hmac.new(
        SECRET_KEY.encode(),
        value.encode(),
        hashlib.sha256
    ).hexdigest()


def _buckets(email: str, client_ip: str) -> list[tuple[str, int]]:
    normalized_email = email.strip().casefold()
    normalized_ip = client_ip or "unknown"
    return [
        (_bucket_hash(f"ip:{normalized_ip}"), MAX_FAILURES_PER_IP),
        (
            _bucket_hash(f"account:{normalized_email}:ip:{normalized_ip}"),
            MAX_FAILURES_PER_ACCOUNT_AND_IP
        )
    ]


def reserve_login_attempt(
    db: Session,
    email: str,
    client_ip: str,
    now: datetime | None = None
) -> int | None:
    current_time = now or _now()
    cutoff = current_time - LOGIN_ATTEMPT_WINDOW
    buckets = _buckets(email, client_ip)
    db.query(LoginThrottle).filter(
        LoginThrottle.window_started_at <= cutoff
    ).delete(synchronize_session=False)

    dialect = db.get_bind().dialect.name
    if dialect not in ("mysql", "sqlite"):
        raise RuntimeError(
            f"Login throttling does not support database dialect {dialect}"
        )
    insert = mysql_insert if dialect == "mysql" else sqlite_insert
    try:
        for key_hash, _ in sorted(buckets):
            statement = insert(LoginThrottle).values(
                key_hash=key_hash,
                window_started_at=current_time,
                attempt_count=0
            )
            if dialect == "mysql":
                statement = statement.on_duplicate_key_update(
                    key_hash=LoginThrottle.key_hash
                )
            elif dialect == "sqlite":
                statement = statement.on_conflict_do_nothing(
                    index_elements=[LoginThrottle.key_hash]
                )
            else:
                raise RuntimeError(
                    "Login throttling does not support database "
                    f"dialect {dialect}"
                )
            db.execute(statement)

        records = db.query(LoginThrottle).filter(
            LoginThrottle.key_hash.in_([key for key, _ in buckets])
        ).order_by(
            LoginThrottle.key_hash.asc()
        ).with_for_update().all()
        records_by_hash = {record.key_hash: record for record in records}
        blocked_until = []
        for key_hash, maximum in buckets:
            record = records_by_hash[key_hash]
            if record.window_started_at <= cutoff:
                record.window_started_at = current_time
                record.attempt_count = 0
            if record.attempt_count >= maximum:
                blocked_until.append(
                    record.window_started_at + LOGIN_ATTEMPT_WINDOW
                )

        if blocked_until:
            db.commit()
            return max(
                1,
                int((max(blocked_until) - current_time).total_seconds())
            )

        for key_hash, _ in buckets:
            records_by_hash[key_hash].attempt_count += 1
        db.commit()
        return None
    except Exception:
        db.rollback()
        raise


def reset_account_ip_attempts(
    db: Session,
    email: str,
    client_ip: str,
    now: datetime | None = None
) -> None:
    current_time = now or _now()
    buckets = _buckets(email, client_ip)
    ip_hash = buckets[0][0]
    account_ip_hash = buckets[1][0]
    db.query(LoginThrottle).filter(
        LoginThrottle.key_hash == ip_hash
    ).update(
        {
            LoginThrottle.attempt_count: case(
                (
                    LoginThrottle.attempt_count > 0,
                    LoginThrottle.attempt_count - 1
                ),
                else_=0
            )
        },
        synchronize_session=False
    )
    db.query(LoginThrottle).filter(
        LoginThrottle.key_hash == account_ip_hash
    ).update(
        {
            LoginThrottle.window_started_at: current_time,
            LoginThrottle.attempt_count: 0
        },
        synchronize_session=False
    )
