from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from fastapi.testclient import TestClient

from backend import add_admin, audit, auth, main, models, reset_admin
from backend.auth import hash_password, verify_password
from backend.database import Base


def test_reset_admin_password(monkeypatch, tmp_path):
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
    monkeypatch.setattr(reset_admin, "SessionLocal", test_session)
    monkeypatch.setattr(main, "SessionLocal", test_session)
    monkeypatch.setattr(audit, "AUDIT_ANCHOR_PATH", tmp_path / ".audit-anchor")
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt: "admin@example.com"
    )
    passwords = iter(("New-secure-password", "New-secure-password"))
    monkeypatch.setattr(reset_admin, "getpass", lambda prompt: next(passwords))

    db = test_session()
    admin = models.User(
        full_name="Administrator",
        email="admin@example.com",
        hashed_password=hash_password("Old-secure-password"),
        role="admin",
        is_active=True,
        auth_version=0
    )
    db.add(admin)
    db.commit()
    admin_id = admin.id
    db.close()

    try:
        with TestClient(main.app) as client:
            old_token = auth.create_access_token(admin_id, auth_version=0)
            assert client.get(
                "/me",
                headers={"Authorization": "Bearer " + old_token}
            ).status_code == 200

            reset_admin.reset_admin_password()

            assert client.get(
                "/me",
                headers={"Authorization": "Bearer " + old_token}
            ).status_code == 401
            login_response = client.post(
                "/login",
                json={
                    "email": "admin@example.com",
                    "password": "New-secure-password"
                }
            )
            assert login_response.status_code == 200
            assert client.get(
                "/me",
                headers={
                    "Authorization": (
                        "Bearer " + login_response.json()["access_token"]
                    )
                }
            ).status_code == 200

        db = test_session()
        updated_admin = db.query(models.User).filter_by(id=admin_id).one()
        assert verify_password(
            "New-secure-password",
            updated_admin.hashed_password
        )
        assert updated_admin.is_active is True
        assert updated_admin.auth_version == 1
        assert db.query(models.AuditLog).filter_by(
            action="ADMIN_PASSWORD_RESET"
        ).count() == 1
        db.close()
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def test_add_additional_admin(monkeypatch, tmp_path):
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
    monkeypatch.setattr(add_admin, "SessionLocal", test_session)
    monkeypatch.setattr(audit, "AUDIT_ANCHOR_PATH", tmp_path / ".audit-anchor")
    answers = iter(("Trustvault Admin", "admin@gmail.com"))
    monkeypatch.setattr("builtins.input", lambda prompt: next(answers))
    passwords = iter(("Test-only-password-2026", "Test-only-password-2026"))
    monkeypatch.setattr(add_admin, "getpass", lambda prompt: next(passwords))

    db = test_session()
    db.add(models.User(
        full_name="Existing Administrator",
        email="existing-admin@example.com",
        hashed_password=hash_password("Old-secure-password"),
        role="admin",
        is_active=True
    ))
    db.commit()
    db.close()

    try:
        add_admin.add_admin_account()

        db = test_session()
        new_admin = db.query(models.User).filter_by(
            email="admin@gmail.com"
        ).one()
        assert new_admin.full_name == "Trustvault Admin"
        assert new_admin.role == "admin"
        assert new_admin.is_active is True
        assert verify_password(
            "Test-only-password-2026",
            new_admin.hashed_password
        )
        assert db.query(models.AuditLog).filter_by(
            action="ADMIN_CREATED"
        ).count() == 1
        db.close()
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
