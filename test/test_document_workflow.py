import asyncio
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import audit, auth, login_throttle, main, models
from backend.database import Base


def create_account(client, name, email, role):
    response = client.post(
        "/register",
        json={
            "full_name": name,
            "email": email,
            "password": "Secure-test-password",
            "role": role
        }
    )
    assert response.status_code == 200
    return response.json()


def login(client, email):
    response = client.post(
        "/login",
        json={
            "email": email,
            "password": "Secure-test-password"
        }
    )
    assert response.status_code == 200
    return {
        "Authorization": "Bearer " + response.json()["access_token"]
    }


def test_owner_document_sharing_workflow(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    test_session = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(audit, "AUDIT_ANCHOR_PATH", tmp_path / ".audit-anchor")
    monkeypatch.setattr(main, "SessionLocal", test_session)

    def override_get_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_get_db

    try:
        with TestClient(main.app) as client:
            login_page = client.get("/")
            assert login_page.status_code == 200
            assert "TrustVault" in login_page.text
            assert client.get("/script.js").status_code == 200
            assert client.get("/dashboard.html").status_code == 200
            allowed_preflight = client.options(
                "/login",
                headers={
                    "Origin": "http://localhost:5500",
                    "Access-Control-Request-Method": "POST"
                }
            )
            assert (
                allowed_preflight.headers["access-control-allow-origin"]
                == "http://localhost:5500"
            )
            denied_preflight = client.options(
                "/login",
                headers={
                    "Origin": "https://untrusted.example",
                    "Access-Control-Request-Method": "POST"
                }
            )
            assert (
                "access-control-allow-origin"
                not in denied_preflight.headers
            )

            admin_registration = client.post(
                "/register",
                json={
                    "full_name": "Untrusted Admin",
                    "email": "admin@example.com",
                    "password": "Secure-test-password",
                    "role": "admin"
                }
            )
            assert admin_registration.status_code == 422

            owner = create_account(
                client,
                "Document Owner",
                "owner@example.com",
                "owner"
            )
            viewer = create_account(
                client,
                "Document Viewer",
                "viewer@example.com",
                "viewer"
            )
            failed_login = client.post(
                "/login",
                json={
                    "email": owner["email"],
                    "password": "Wrong-test-password"
                }
            )
            assert failed_login.status_code == 401
            owner_headers = login(client, owner["email"])
            viewer_headers = login(client, viewer["email"])
            assert client.get(
                "/me",
                headers={"Authorization": "Bearer invalid-token"}
            ).status_code == 401
            expired_token = jwt.encode(
                {
                    "sub": str(owner["user_id"]),
                    "exp": datetime.now(timezone.utc) - timedelta(minutes=1)
                },
                auth.SECRET_KEY,
                algorithm=auth.ALGORITHM
            )
            assert client.get(
                "/me",
                headers={"Authorization": "Bearer " + expired_token}
            ).status_code == 401

            assert owner["role"] == "owner"
            assert viewer["role"] == "viewer"

            viewers_response = client.get(
                "/users/viewers",
                headers=owner_headers
            )
            assert viewers_response.status_code == 200
            assert viewers_response.json()["viewers"] == [{
                "user_id": viewer["user_id"],
                "full_name": "Document Viewer",
                "email": "viewer@example.com"
            }]
            assert client.get(
                "/users/viewers",
                headers=viewer_headers
            ).status_code == 403

            upload_response = client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Personal"},
                files={
                    "file": (
                        "notes.txt",
                        b"private document contents",
                        "text/plain"
                    )
                }
            )
            assert upload_response.status_code == 200
            document_id = upload_response.json()["document_id"]

            documents_response = client.get(
                "/documents/mine",
                headers=owner_headers
            )
            assert documents_response.status_code == 200
            document = documents_response.json()["documents"][0]
            assert document["document_id"] == document_id
            assert document["owner_name"] == "Document Owner"
            assert document["owner_email"] == "owner@example.com"
            assert document["created_at"]
            assert document["permissions"] == []

            other_owner = create_account(
                client,
                "Another Owner",
                "another-owner@example.com",
                "owner"
            )
            other_owner_headers = login(client, other_owner["email"])
            duplicate_name_response = client.post(
                "/documents/upload",
                headers=other_owner_headers,
                data={"category": "Private"},
                files={
                    "file": (
                        "notes.txt",
                        b"another owner's private document",
                        "text/plain"
                    )
                }
            )
            assert duplicate_name_response.status_code == 200
            other_document_id = duplicate_name_response.json()["document_id"]
            lookup_db = test_session()
            other_document = lookup_db.query(models.Document).filter_by(
                id=other_document_id
            ).one()
            owner_document = lookup_db.query(models.Document).filter_by(
                id=document_id
            ).one()
            assert other_document.filename == owner_document.filename
            assert other_document.storage_path != owner_document.storage_path
            assert other_document.content_type == "text/plain"
            other_storage_path = other_document.storage_path
            lookup_db.close()
            assert client.get(
                f"/uploads/{Path(other_storage_path).name}",
                headers=owner_headers
            ).status_code == 404
            cross_owner_responses = (
                client.get(
                    f"/documents/{other_document_id}/view",
                    headers=owner_headers
                ),
                client.get(
                    f"/documents/{other_document_id}/download",
                    headers=owner_headers
                ),
                client.patch(
                    f"/documents/{other_document_id}",
                    headers=owner_headers,
                    json={"category": "Stolen"}
                ),
                client.delete(
                    f"/documents/{other_document_id}",
                    headers=owner_headers
                ),
                client.post(
                    f"/documents/{other_document_id}/share",
                    headers=owner_headers,
                    json={
                        "viewer_user_id": viewer["user_id"],
                        "can_read": True
                    }
                ),
                client.delete(
                    f"/documents/{other_document_id}/share/{viewer['user_id']}",
                    headers=owner_headers
                )
            )
            for response in cross_owner_responses:
                assert response.status_code in (403, 404)
                assert b"another owner's private document" not in response.content
                assert other_storage_path.encode() not in response.content

            assert client.get(
                f"/documents/{document_id}/activity",
                headers=owner_headers
            ).status_code == 200
            assert client.get(
                f"/documents/{document_id}/activity",
                headers=viewer_headers
            ).status_code == 403
            assert client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "payload.exe",
                        b"not an allowed document type",
                        "application/octet-stream"
                    )
                }
            ).status_code == 400
            assert client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "spoofed.txt",
                        b"plain text content",
                        "application/pdf"
                    )
                }
            ).status_code == 400
            assert client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "mismatch.pdf",
                        b"plain text content",
                        "application/pdf"
                    )
                }
            ).status_code == 400
            assert client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "invalid.png",
                        b"not a PNG file",
                        "image/png"
                    )
                }
            ).status_code == 400
            assert client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "oversized.txt",
                        b"a" * (main.MAX_FILE_SIZE + 1),
                        "text/plain"
                    )
                }
            ).status_code == 400
            oversized_request = client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "oversized-request.txt",
                        b"a" * main.MAX_UPLOAD_REQUEST_SIZE,
                        "text/plain"
                    )
                }
            )
            assert oversized_request.status_code == 413
            traversal_upload = client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Path test"},
                files={
                    "file": (
                        "..\\..\\outside.txt",
                        b"safe content",
                        "text/plain"
                    )
                }
            )
            assert traversal_upload.status_code == 200
            lookup_db = test_session()
            traversal_document = lookup_db.query(
                models.Document
            ).filter_by(id=traversal_upload.json()["document_id"]).one()
            assert traversal_document.filename == "outside.txt"
            assert Path(traversal_document.storage_path).resolve().parent == (
                tmp_path.resolve()
            )
            lookup_db.close()
            stored_files_before_failure = set(tmp_path.glob("*.txt"))

            def fail_audit_write(*args, **kwargs):
                raise RuntimeError("Simulated audit storage failure")

            with monkeypatch.context() as patch:
                patch.setattr(main, "create_audit_log", fail_audit_write)
                failed_upload = client.post(
                    "/documents/upload",
                    headers=owner_headers,
                    data={"category": "Audit failure"},
                    files={
                        "file": (
                            "cleanup.txt",
                            b"this file must be removed",
                            "text/plain"
                        )
                    }
                )
            assert failed_upload.status_code == 503
            assert set(tmp_path.glob("*.txt")) == stored_files_before_failure
            assert client.post(
                "/documents/upload",
                headers=viewer_headers,
                data={"category": "Invalid"},
                files={
                    "file": (
                        "notes.txt",
                        b"viewer cannot upload",
                        "text/plain"
                    )
                }
            ).status_code == 403

            assert client.get(
                f"/documents/{document_id}/view",
                headers=viewer_headers
            ).status_code == 403
            assert client.patch(
                f"/documents/{document_id}",
                headers={
                    **viewer_headers,
                    "X-Forwarded-For": "203.0.113.99"
                },
                json={"category": "Unauthorized edit"}
            ).status_code == 403
            assert client.post(
                f"/documents/{document_id}/share",
                headers=viewer_headers,
                json={
                    "viewer_user_id": owner["user_id"],
                    "can_read": True
                }
            ).status_code == 403

            share_response = client.post(
                f"/documents/{document_id}/share",
                headers=owner_headers,
                json={
                    "viewer_user_id": viewer["user_id"],
                    "can_read": True,
                    "can_edit": True,
                    "can_download": False
                }
            )
            assert share_response.status_code == 200

            listed_documents = client.get(
                "/documents/mine",
                headers=owner_headers
            ).json()["documents"]
            updated_document = next(
                item for item in listed_documents
                if item["document_id"] == document_id
            )
            assert updated_document["permissions"] == [{
                "user_id": viewer["user_id"],
                "full_name": "Document Viewer",
                "email": "viewer@example.com",
                "can_read": True,
                "can_edit": True,
                "can_download": False
            }]

            shared_response = client.get(
                "/documents/shared-with-me",
                headers=viewer_headers
            )
            assert shared_response.status_code == 200
            assert shared_response.json()["total_documents"] == 1
            shared_document = shared_response.json()["documents"][0]
            assert shared_document["owner_name"] == "Document Owner"
            assert shared_document["owner_email"] == "owner@example.com"
            assert client.get(
                f"/documents/{document_id}/view",
                headers=viewer_headers
            ).content == b"private document contents"
            assert client.get(
                f"/documents/{document_id}/download",
                headers=viewer_headers
            ).status_code == 403

            edit_response = client.patch(
                f"/documents/{document_id}",
                headers=viewer_headers,
                json={"category": "Edited by viewer"}
            )
            assert edit_response.status_code == 200
            assert edit_response.json()["category"] == "Edited by viewer"

            update_permission_response = client.post(
                f"/documents/{document_id}/share",
                headers=owner_headers,
                json={
                    "viewer_user_id": viewer["user_id"],
                    "can_read": True,
                    "can_edit": True,
                    "can_download": True
                }
            )
            assert update_permission_response.status_code == 200

            download_response = client.get(
                f"/documents/{document_id}/download",
                headers=viewer_headers
            )
            assert download_response.status_code == 200
            assert download_response.content == b"private document contents"

            revoke_response = client.delete(
                f"/documents/{document_id}/share/{viewer['user_id']}",
                headers=owner_headers
            )
            assert revoke_response.status_code == 200
            assert client.get(
                "/documents/shared-with-me",
                headers=viewer_headers
            ).json()["total_documents"] == 0
            assert client.get(
                f"/documents/{document_id}/download",
                headers=viewer_headers
            ).status_code == 403
            assert client.get(
                f"/documents/{document_id}/view",
                headers=viewer_headers
            ).status_code == 403

            assert client.delete(
                f"/documents/{document_id}",
                headers=viewer_headers
            ).status_code == 403
            assert client.delete(
                f"/documents/{document_id}",
                headers=owner_headers
            ).status_code == 200
            remaining_documents = client.get(
                "/documents/mine",
                headers=owner_headers
            ).json()["documents"]
            assert all(
                item["document_id"] != document_id
                for item in remaining_documents
            )
            assert client.get(
                f"/documents/{document_id}/download",
                headers=owner_headers
            ).status_code == 404
            assert client.post(
                f"/documents/{document_id}/restore",
                headers=owner_headers
            ).status_code == 200
            assert client.get(
                f"/documents/{document_id}/view",
                headers=owner_headers
            ).content == b"private document contents"
            assert client.delete(
                f"/documents/{document_id}",
                headers=owner_headers
            ).status_code == 200
            recycle_bin = client.get(
                "/documents/recycle-bin",
                headers=owner_headers
            )
            assert recycle_bin.status_code == 200
            deleted_entry = next(
                item for item in recycle_bin.json()["documents"]
                if item["document_id"] == document_id
            )
            assert deleted_entry["purged_at"] is None

            purge_lookup = test_session()
            purge_document = purge_lookup.query(models.Document).filter_by(
                id=document_id
            ).one()
            private_file = Path(purge_document.storage_path)
            assert private_file.is_file()
            purge_lookup.close()
            assert client.post(
                f"/documents/{document_id}/purge",
                headers=viewer_headers
            ).status_code == 403
            assert client.post(
                f"/documents/{document_id}/purge",
                headers=other_owner_headers
            ).status_code == 404
            purge_response = client.post(
                f"/documents/{document_id}/purge",
                headers=owner_headers
            )
            assert purge_response.status_code == 200
            assert purge_response.json()["metadata_retained"] is True
            assert not private_file.exists()
            assert client.post(
                f"/documents/{document_id}/restore",
                headers=owner_headers
            ).status_code == 404
            purged_documents = client.get(
                "/documents/recycle-bin",
                headers=owner_headers
            ).json()["documents"]
            purged_entry = next(
                item for item in purged_documents
                if item["document_id"] == document_id
            )
            assert purged_entry["purged_at"]

            assert client.post(
                "/logout",
                headers=owner_headers
            ).status_code == 200
            assert client.get("/me", headers=owner_headers).status_code == 401

            audit_db = test_session()
            try:
                request_events = audit_db.query(
                    models.AuditLog
                ).filter_by(action="DOCUMENT_REQUEST").all()
                assert any(
                    event.actor_id == viewer["user_id"]
                    and event.details["method"] == "PATCH"
                    and event.details["path"] == f"/documents/{document_id}"
                    and event.details["status_code"] == 403
                    and event.details["outcome"] == "denied"
                    and event.document_id == document_id
                    and event.details["required_permission"] == "can_edit"
                    and event.details["client_ip"] == "testclient"
                    for event in request_events
                )
                assert any(
                    event.actor_id == viewer["user_id"]
                    and event.details["method"] == "GET"
                    and event.details["path"] ==
                        f"/documents/{document_id}/download"
                    and event.details["status_code"] == 200
                    and event.details["outcome"] == "success"
                    and event.details["required_permission"] == "can_download"
                    for event in request_events
                )
                assert any(
                    event.actor_id == owner["user_id"]
                    and event.details["path"] == "/documents/upload"
                    and event.details["status_code"] == 413
                    and event.details["outcome"] == "failure"
                    for event in request_events
                )
                assert any(
                    event.actor_id == viewer["user_id"]
                    and event.details["path"] ==
                        f"/documents/{document_id}/purge"
                    and event.details["status_code"] == 403
                    and event.details["outcome"] == "denied"
                    and event.details["required_permission"] == "owner_purge"
                    for event in request_events
                )
                assert any(
                    event.action == "DOCUMENT_FILE_PURGED"
                    and event.actor_id == owner["user_id"]
                    and event.document_id == document_id
                    and event.details["active_storage_file_removed"] is True
                    and event.details["metadata_retained"] is True
                    for event in audit_db.query(models.AuditLog).all()
                )
                document_actions = {
                    event.action
                    for event in audit_db.query(models.AuditLog).filter_by(
                        document_id=document_id
                    ).all()
                }
                assert "DOCUMENT_MOVED_TO_RECYCLE_BIN" in document_actions
                assert "DOCUMENT_RESTORED" in document_actions
                assert any(
                    event.action == "USER_LOGIN_FAILED"
                    and event.details["outcome"] == "failure"
                    and event.details["client_ip"] == "testclient"
                    for event in audit_db.query(models.AuditLog).all()
                )
                all_details = repr([
                    event.details
                    for event in audit_db.query(models.AuditLog).all()
                ])
                assert "Wrong-test-password" not in all_details
                assert owner_headers["Authorization"] not in all_details
                assert any(
                    event.action == "LOGIN_ATTEMPT"
                    and event.details["outcome"] == "failure"
                    and event.details["required_permission"] == "authenticate"
                    for event in audit_db.query(models.AuditLog).all()
                )
                assert all(
                    "outcome" in event.details
                    for event in audit_db.query(models.AuditLog).all()
                )
                assert audit.verify_audit_chain(audit_db)["valid"] is True
                last_log = audit_db.query(models.AuditLog).order_by(
                    models.AuditLog.id.desc()
                ).first()
                last_log.details = {"tampered": True}
                with pytest.raises(ValueError, match="append-only"):
                    audit_db.commit()
                audit_db.rollback()
                with pytest.raises(ValueError, match="append-only"):
                    audit_db.query(models.AuditLog).delete()
                audit_db.rollback()
                with pytest.raises(ValueError, match="append-only"):
                    audit_db.query(models.AuditLog).update({
                        models.AuditLog.action: "TAMPERED"
                    })
                audit_db.rollback()
                last_log = audit_db.query(models.AuditLog).order_by(
                    models.AuditLog.id.desc()
                ).first()
                audit_db.execute(
                    text(
                        "UPDATE audit_logs SET details = :details WHERE id = :id"
                    ),
                    {
                        "details": '{"tampered": true}',
                        "id": last_log.id
                    }
                )
                audit_db.commit()
                assert audit.verify_audit_chain(audit_db)["valid"] is False
                audit_db.execute(text("DELETE FROM audit_logs"))
                audit_db.commit()
                assert audit.verify_audit_chain(audit_db)["valid"] is False
            finally:
                audit_db.close()
    finally:
        main.app.dependency_overrides.pop(main.get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_admin_user_management_and_suspension(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    test_session = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(main, "UPLOAD_DIR", tmp_path)
    monkeypatch.setattr(audit, "AUDIT_ANCHOR_PATH", tmp_path / ".audit-anchor")
    monkeypatch.setattr(main, "SessionLocal", test_session)

    def override_get_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_get_db
    try:
        admin_db = test_session()
        admin = models.User(
            full_name="TrustVault Admin",
            email="admin@example.com",
            hashed_password=main.hash_password("Secure-test-password"),
            role="admin",
            is_active=True
        )
        admin_db.add(admin)
        admin_db.commit()
        admin_db.refresh(admin)
        admin_id = admin.id
        admin_db.close()

        with TestClient(main.app) as client:
            viewer = create_account(
                client,
                "Managed Viewer",
                "managed-viewer@example.com",
                "viewer"
            )
            admin_headers = login(client, "admin@example.com")
            viewer_headers = login(client, viewer["email"])

            user_list = client.get(
                "/admin/users",
                headers=admin_headers
            )
            assert user_list.status_code == 200
            assert len(user_list.json()["users"]) == 2
            assert client.get(
                "/admin/users",
                headers=viewer_headers
            ).status_code == 403

            assert client.patch(
                f"/admin/users/{admin_id}",
                headers=admin_headers,
                json={"is_active": False}
            ).status_code == 400

            assert client.patch(
                f"/admin/users/{viewer['user_id']}",
                headers=admin_headers,
                json={"is_active": False}
            ).status_code == 200
            assert client.get("/me", headers=viewer_headers).status_code == 403

            assert client.patch(
                f"/admin/users/{viewer['user_id']}",
                headers=admin_headers,
                json={"is_active": True, "role": "owner"}
            ).status_code == 200
            assert client.get("/me", headers=viewer_headers).status_code == 200

            assert client.patch(
                f"/admin/users/{viewer['user_id']}",
                headers=admin_headers,
                json={"role": "viewer"}
            ).status_code == 200
            assert client.patch(
                f"/admin/users/{admin_id}",
                headers=admin_headers,
                json={"role": "viewer"}
            ).status_code == 400

            owner = create_account(
                client,
                "Private Document Owner",
                "private-owner@example.com",
                "owner"
            )
            owner_headers = login(client, owner["email"])
            upload_response = client.post(
                "/documents/upload",
                headers=owner_headers,
                data={"category": "Private"},
                files={
                    "file": (
                        "private.txt",
                        b"admin has no automatic access",
                        "text/plain"
                    )
                }
            )
            assert upload_response.status_code == 200
            private_document_id = upload_response.json()["document_id"]
            assert client.post(
                f"/documents/{private_document_id}/share",
                headers=owner_headers,
                json={
                    "viewer_user_id": viewer["user_id"],
                    "can_read": True,
                    "can_edit": False,
                    "can_download": False
                }
            ).status_code == 200
            assert client.delete(
                f"/documents/{private_document_id}/share/{viewer['user_id']}",
                headers=owner_headers
            ).status_code == 200
            admin_dashboard = client.get(
                "/admin/dashboard",
                headers=admin_headers
            )
            assert admin_dashboard.status_code == 200
            assert admin_dashboard.json()["total_users"] == 3
            assert admin_dashboard.json()["total_documents"] == 1
            assert client.get(
                "/admin/dashboard",
                headers=viewer_headers
            ).status_code == 403
            assert client.get(
                f"/documents/{private_document_id}/view",
                headers=admin_headers
            ).status_code == 403
            assert client.get(
                f"/documents/{private_document_id}/download",
                headers=admin_headers
            ).status_code == 403
            assert client.patch(
                f"/admin/users/{owner['user_id']}",
                headers=admin_headers,
                json={"role": "viewer"}
            ).status_code == 409
            audit_logs_response = client.get(
                "/admin/audit-logs",
                headers=admin_headers
            )
            assert audit_logs_response.status_code == 200
            audit_actions = {
                log["action"]
                for log in audit_logs_response.json()["audit_logs"]
            }
            assert "DOCUMENT_UPLOADED" in audit_actions
            assert "DOCUMENT_REQUEST" in audit_actions
            assert "PERMISSION_GRANTED_OR_UPDATED" in audit_actions
            assert "PERMISSION_REVOKED" in audit_actions
            admin_login = next(
                log for log in audit_logs_response.json()["audit_logs"]
                if log["action"] == "USER_LOGGED_IN"
                and log["actor_id"] == admin_id
            )
            assert {
                key: admin_login["details"][key]
                for key in ("full_name", "email")
            } == {
                "full_name": "TrustVault Admin",
                "email": "admin@example.com"
            }
            assert admin_login["details"]["outcome"] == "success"
            assert admin_login["details"]["client_ip"] == "testclient"
            assert admin_login["created_at"].endswith("+00:00")
            assert client.get(
                "/admin/audit-logs/verify",
                headers=admin_headers
            ).json()["valid"] is True
            assert client.post(
                "/logout",
                headers=admin_headers
            ).status_code == 200
            assert client.get("/me", headers=admin_headers).status_code == 401
    finally:
        main.app.dependency_overrides.pop(main.get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_dashboard_uses_text_nodes_for_untrusted_metadata():
    dashboard = (
        Path(__file__).resolve().parent.parent
        / "frontend"
        / "dashboard.html"
    ).read_text(encoding="utf-8")

    assert 'name.textContent = "📄 " + doc.filename;' in dashboard
    assert "category.textContent =" in dashboard
    assignments = re.findall(
        r"\.innerHTML\s*=\s*([^;\n]*)",
        dashboard
    )
    assert all(
        assignment.strip().startswith(("'", '"'))
        for assignment in assignments
    )
    for search_field in (
        "doc.filename",
        "doc.category",
        "doc.owner_name",
        "doc.owner_email",
        "doc.created_at"
    ):
        assert search_field in dashboard
    for date_control in (
        "ownerDateFrom",
        "ownerDateTo",
        "sharedDateFrom",
        "sharedDateTo"
    ):
        assert date_control in dashboard


def test_login_rate_limit_is_persistent_and_expires(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    test_session = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine
    )
    Base.metadata.create_all(bind=engine)
    monkeypatch.setattr(audit, "AUDIT_ANCHOR_PATH", tmp_path / ".audit-anchor")
    monkeypatch.setattr(main, "SessionLocal", test_session)
    monkeypatch.setattr(login_throttle, "MAX_FAILURES_PER_IP", 4)
    monkeypatch.setattr(
        login_throttle,
        "MAX_FAILURES_PER_ACCOUNT_AND_IP",
        2
    )

    def override_get_db():
        db = test_session()
        try:
            yield db
        finally:
            db.close()

    main.app.dependency_overrides[main.get_db] = override_get_db
    try:
        with TestClient(main.app) as client:
            owner = create_account(
                client,
                "Rate Limited Owner",
                "rate-limit@example.com",
                "owner"
            )
            for _ in range(6):
                successful_login = client.post(
                    "/login",
                    json={
                        "email": owner["email"],
                        "password": "Secure-test-password"
                    }
                )
                assert successful_login.status_code == 200

            bad_credentials = {
                "email": owner["email"],
                "password": "Wrong-test-password"
            }
            assert client.post("/login", json=bad_credentials).status_code == 401
            assert client.post("/login", json=bad_credentials).status_code == 401
            blocked = client.post(
                "/login",
                json={
                    "email": owner["email"],
                    "password": "Secure-test-password"
                }
            )
            assert blocked.status_code == 429
            assert int(blocked.headers["retry-after"]) > 0
            assert "Try again in" in blocked.json()["detail"]

            for email in ("first@example.com", "second@example.com"):
                assert client.post(
                    "/login",
                    json={
                        "email": email,
                        "password": "Wrong-test-password"
                    }
                ).status_code == 401
            ip_blocked = client.post(
                "/login",
                json={
                    "email": "third@example.com",
                    "password": "Wrong-test-password"
                }
            )
            assert ip_blocked.status_code == 429

            db = test_session()
            throttle_records = db.query(models.LoginThrottle).all()
            assert throttle_records
            assert all(len(record.key_hash) == 64 for record in throttle_records)
            assert all(
                "rate-limit@example.com" not in record.key_hash
                and "testclient" not in record.key_hash
                for record in throttle_records
            )
            expired_at = (
                datetime.now(timezone.utc) -
                login_throttle.LOGIN_ATTEMPT_WINDOW -
                timedelta(seconds=1)
            ).replace(tzinfo=None)
            db.query(models.LoginThrottle).update({
                models.LoginThrottle.window_started_at: expired_at
            })
            db.commit()
            db.close()

            recovered = client.post(
                "/login",
                json={
                    "email": owner["email"],
                    "password": "Secure-test-password"
                }
            )
            assert recovered.status_code == 200

            audit_db = test_session()
            assert audit.verify_audit_chain(audit_db)["valid"] is True
            audit_db.close()
    finally:
        main.app.dependency_overrides.pop(main.get_db, None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_upload_request_limit_enforces_stream_without_content_length(
    monkeypatch
):
    monkeypatch.setattr(main, "MAX_UPLOAD_REQUEST_SIZE", 10)

    async def consume_request_body(scope, receive, send):
        await receive()

    async def receive():
        return {
            "type": "http.request",
            "body": b"x" * 11,
            "more_body": False
        }

    async def send(message):
        return None

    async def run_middleware():
        middleware = main.UploadRequestSizeLimitMiddleware(
            consume_request_body
        )
        scope = {
            "type": "http",
            "path": "/documents/upload",
            "headers": []
        }
        with pytest.raises(main.HTTPException) as error:
            await middleware(scope, receive, send)
        assert error.value.status_code == 413

    asyncio.run(run_middleware())
