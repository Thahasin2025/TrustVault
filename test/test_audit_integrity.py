import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import audit, auth, main, models
from backend.database import Base


@pytest.fixture
def audit_test_sessions(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    test_session = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
    monkeypatch.setattr(
        audit,
        "AUDIT_ANCHOR_PATH",
        tmp_path / ".audit-anchor"
    )
    try:
        yield test_session
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def _append_two_events(db):
    first = audit.create_audit_log(
        db,
        actor_id=None,
        document_id=None,
        action="TEST_FIRST_EVENT"
    )
    db.commit()
    second = audit.create_audit_log(
        db,
        actor_id=None,
        document_id=None,
        action="TEST_SECOND_EVENT"
    )
    db.commit()
    return first.id, second.id


def test_new_audit_events_are_linked_and_verified(audit_test_sessions):
    db = audit_test_sessions()
    try:
        first_id, second_id = _append_two_events(db)

        result = audit.verify_audit_chain(db)

        assert result["valid"] is True
        assert result["checked_logs"] == 2
        assert result["checked_records"] == 2
        assert result["valid_records"] == 2
        assert result["invalid_records"] == 0
        assert result["affected_record_id"] is None
        first, second = db.query(models.AuditLog).order_by(
            models.AuditLog.id.asc()
        ).all()
        assert first.id == first_id
        assert first.previous_hash == "GENESIS"
        assert second.id == second_id
        assert second.previous_hash == first.current_hash
        assert audit._read_anchor() == {
            "last_log_id": second.id,
            "current_hash": second.current_hash
        }
    finally:
        db.close()


@pytest.mark.parametrize("tamper", ["record", "hash"])
def test_audit_verification_detects_modified_record_and_invalid_hash(
    audit_test_sessions,
    tamper
):
    db = audit_test_sessions()
    try:
        first_id, _ = _append_two_events(db)
        if tamper == "record":
            db.execute(
                text("UPDATE audit_logs SET action = :action WHERE id = :id"),
                {"action": "ALTERED_EVENT", "id": first_id}
            )
        else:
            db.execute(
                text(
                    "UPDATE audit_logs SET current_hash = :hash WHERE id = :id"
                ),
                {"hash": "0" * 64, "id": first_id}
            )
        db.commit()

        result = audit.verify_audit_chain(db)

        assert result["valid"] is False
        assert result["reason"] == f"Invalid hash at audit log {first_id}"
    finally:
        db.close()


def test_audit_verification_detects_broken_previous_hash(
    audit_test_sessions
):
    db = audit_test_sessions()
    try:
        _, second_id = _append_two_events(db)
        db.execute(
            text(
                "UPDATE audit_logs SET previous_hash = :hash WHERE id = :id"
            ),
            {"hash": "broken-link", "id": second_id}
        )
        db.commit()

        result = audit.verify_audit_chain(db)

        assert result["valid"] is False
        assert result["reason"] == f"Broken hash chain at audit log {second_id}"
    finally:
        db.close()


def test_audit_verification_accepts_configured_historical_key(
    audit_test_sessions,
    monkeypatch
):
    db = audit_test_sessions()
    try:
        _, second_id = _append_two_events(db)
        first, second = db.query(models.AuditLog).order_by(
            models.AuditLog.id.asc()
        ).all()
        historical_key = b"historical-audit-verification-key-32"
        first_payload = {
            **audit._serialize_log(first),
            "previous_hash": first.previous_hash
        }
        historical_hash = audit._signed_hash_with_key(
            first_payload,
            historical_key
        )
        second_payload = {
            **audit._serialize_log(second),
            "previous_hash": historical_hash
        }
        second_hash = audit._signed_hash(second_payload)

        db.execute(
            text(
                "UPDATE audit_logs SET current_hash = :hash WHERE id = :id"
            ),
            {"hash": historical_hash, "id": first.id}
        )
        db.execute(
            text(
                "UPDATE audit_logs "
                "SET previous_hash = :previous_hash, current_hash = :hash "
                "WHERE id = :id"
            ),
            {
                "previous_hash": historical_hash,
                "hash": second_hash,
                "id": second.id
            }
        )
        db.commit()
        db.expire_all()
        audit._write_anchor(second_id, second_hash)
        monkeypatch.setattr(
            audit,
            "AUDIT_HMAC_VERIFY_KEYS",
            (historical_key,)
        )

        result = audit.verify_audit_chain(db)

        assert result["valid"] is True
        assert result["checked_records"] == 2
        assert result["valid_records"] == 2
        assert result["invalid_records"] == 0
    finally:
        db.close()


def test_admin_activity_includes_actor_role_and_saves_successful_verification(
    audit_test_sessions
):
    db = audit_test_sessions()
    try:
        admin = models.User(
            full_name="Audit Admin",
            email="activity-admin@example.test",
            hashed_password="unused",
            role="admin",
            is_active=True
        )
        owner = models.User(
            full_name="Document Owner",
            email="activity-owner@example.test",
            hashed_password="unused",
            role="owner",
            is_active=True
        )
        db.add_all([admin, owner])
        db.commit()
        admin_id = admin.id
        owner_id = owner.id

        log = audit.create_audit_log(
            db,
            actor_id=owner_id,
            document_id=None,
            action="USER_LOGGED_IN",
            details={"outcome": "success"}
        )
        db.commit()
        log_id = log.id

        def override_get_db():
            request_db = audit_test_sessions()
            try:
                yield request_db
            finally:
                request_db.close()

        main.app.dependency_overrides[main.get_db] = override_get_db
        try:
            with TestClient(main.app) as client:
                admin_token = auth.create_access_token(admin_id)
                headers = {"Authorization": "Bearer " + admin_token}

                activity = client.get(
                    "/admin/audit-logs",
                    headers=headers
                )
                assert activity.status_code == 200
                event = next(
                    row for row in activity.json()["audit_logs"]
                    if row["id"] == log_id
                )
                assert event["actor_name"] == "Document Owner"
                assert event["actor_role"] == "owner"

                response = client.get(
                    "/admin/audit-logs/verify",
                    headers=headers
                )
                assert response.status_code == 200
                result = response.json()
                assert result["valid"] is True
                assert result["checked_records"] == 1
                assert result["valid_records"] == 1
                assert result["invalid_records"] == 0
                assert result["analysis"]["invalid_record_ranges"] == []
                assert result["analysis"]["current_key_valid_suffix"] == {
                    "count": 1,
                    "first_id": log_id,
                    "last_id": log_id
                }

                stored = client.get(
                    "/admin/audit-logs/verification",
                    headers=headers
                )
                assert stored.status_code == 200
                assert stored.json()["verification"]["verified_at"] == (
                    result["verified_at"]
                )
                assert stored.json()["verification"]["valid"] is True
                assert stored.json()["verification"]["analysis"] == (
                    result["analysis"]
                )
        finally:
            main.app.dependency_overrides.pop(main.get_db, None)
    finally:
        db.close()


def test_admin_verification_is_protected_and_reports_invalid_chain(
    audit_test_sessions
):
    db = audit_test_sessions()
    try:
        admin = models.User(
            full_name="Audit Admin",
            email="audit-admin@example.test",
            hashed_password="unused",
            role="admin",
            is_active=True
        )
        viewer = models.User(
            full_name="Audit Viewer",
            email="audit-viewer@example.test",
            hashed_password="unused",
            role="viewer",
            is_active=True
        )
        db.add_all([admin, viewer])
        db.commit()
        admin_id = admin.id
        viewer_id = viewer.id
        audit_log_id, _ = _append_two_events(db)
        db.execute(
            text("UPDATE audit_logs SET details = :details WHERE id = :id"),
            {"details": json.dumps({"altered": True}), "id": audit_log_id}
        )
        db.commit()

        def override_get_db():
            request_db = audit_test_sessions()
            try:
                yield request_db
            finally:
                request_db.close()

        main.app.dependency_overrides[main.get_db] = override_get_db
        try:
            with TestClient(main.app) as client:
                viewer_token = auth.create_access_token(viewer_id)
                admin_token = auth.create_access_token(admin_id)

                denied = client.get(
                    "/admin/audit-logs/verify",
                    headers={"Authorization": "Bearer " + viewer_token}
                )
                assert denied.status_code == 403
                history_denied = client.get(
                    "/admin/audit-logs/verification",
                    headers={"Authorization": "Bearer " + viewer_token}
                )
                assert history_denied.status_code == 403

                history_before_verification = client.get(
                    "/admin/audit-logs/verification",
                    headers={"Authorization": "Bearer " + admin_token}
                )
                assert history_before_verification.status_code == 200
                assert history_before_verification.json() == {
                    "verification": None
                }

                response = client.get(
                    "/admin/audit-logs/verify",
                    headers={"Authorization": "Bearer " + admin_token}
                )
                assert response.status_code == 200
                result = response.json()
                assert result["valid"] is False
                assert result["reason"] == (
                    f"Invalid hash at audit log {audit_log_id}"
                )
                assert result["checked_records"] == 2
                assert result["valid_records"] == 1
                assert result["invalid_records"] == 1
                assert result["affected_record_id"] == audit_log_id
                assert result["analysis"]["invalid_record_ranges"] == [{
                    "first_id": audit_log_id,
                    "last_id": audit_log_id,
                    "count": 1
                }]
                assert result["analysis"]["current_key_valid_suffix"] == {
                    "count": 1,
                    "first_id": audit_log_id + 1,
                    "last_id": audit_log_id + 1
                }
                assert result["verified_at"]

                stored_history = client.get(
                    "/admin/audit-logs/verification",
                    headers={"Authorization": "Bearer " + admin_token}
                )
                assert stored_history.status_code == 200
                stored_verification = stored_history.json()["verification"]
                assert {
                    key: stored_verification[key]
                    for key in (
                        "verified_at",
                        "valid",
                        "checked_records",
                        "valid_records",
                        "invalid_records",
                        "reason",
                        "affected_record_id"
                    )
                } == {
                    "verified_at": result["verified_at"],
                    "valid": False,
                    "checked_records": 2,
                    "valid_records": 1,
                    "invalid_records": 1,
                    "reason": result["reason"],
                    "affected_record_id": audit_log_id
                }
                assert stored_verification["analysis"] == result["analysis"]
        finally:
            main.app.dependency_overrides.pop(main.get_db, None)

        dashboard = (
            Path(__file__).resolve().parent.parent
            / "frontend"
            / "dashboard.html"
        ).read_text(encoding="utf-8")
        assert '"/admin/audit-logs/verification"' in dashboard
        assert '"No verification has been performed yet."' in dashboard
        assert '"Tampered or Invalid Records"' in dashboard
        assert "cannot safely distinguish between them." in dashboard
        assert '"Existing records still failing verification"' in dashboard
        assert '"Newest records and the current signing key"' in dashboard
    finally:
        db.close()
