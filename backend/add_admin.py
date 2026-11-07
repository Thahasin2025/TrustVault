from getpass import getpass

from pydantic import EmailStr, TypeAdapter

from backend import models
from backend.audit import create_audit_log
from backend.auth import hash_password
from backend.database import SessionLocal


def add_admin_account() -> None:
    full_name = input("Administrator name: ").strip()
    email = str(TypeAdapter(EmailStr).validate_python(
        input("Administrator email: ").strip()
    ))
    password = getpass("Administrator password (12+ characters): ")
    confirmation = getpass("Confirm password: ")

    if not full_name:
        raise ValueError("Administrator name cannot be empty")
    if len(full_name) > 100:
        raise ValueError("Administrator name cannot exceed 100 characters")
    if len(password) < 12:
        raise ValueError("Administrator password must be at least 12 characters")
    if password != confirmation:
        raise ValueError("Passwords do not match")

    db = SessionLocal()
    try:
        existing_user = db.query(models.User.id).filter(
            models.User.email == email
        ).first()
        if existing_user:
            raise RuntimeError(
                "An account with that email already exists; "
                "use the existing account or choose another email"
            )

        admin = models.User(
            full_name=full_name,
            email=email,
            hashed_password=hash_password(password),
            role="admin",
            is_active=True
        )
        db.add(admin)
        db.flush()
        create_audit_log(
            db,
            None,
            None,
            "ADMIN_CREATED",
            {"user_id": admin.id, "source": "local_cli"}
        )
        db.commit()
        print("Administrator account created.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    add_admin_account()
