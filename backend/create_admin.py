from getpass import getpass

from pydantic import EmailStr, TypeAdapter

from backend import models
from backend.audit import create_audit_log
from backend.auth import hash_password
from backend.database import SessionLocal


def create_initial_admin() -> None:
    full_name = input("Administrator name: ").strip()
    email = str(TypeAdapter(EmailStr).validate_python(
        input("Administrator email: ").strip()
    ))
    password = getpass("Administrator password (12+ characters): ")
    confirmation = getpass("Confirm password: ")

    if not full_name:
        raise ValueError("Administrator name cannot be empty")
    if len(password) < 12:
        raise ValueError("Administrator password must be at least 12 characters")
    if password != confirmation:
        raise ValueError("Passwords do not match")

    db = SessionLocal()
    try:
        if db.query(models.User.id).filter(
            models.User.role == "admin"
        ).first():
            raise RuntimeError(
                "An administrator already exists; ask an administrator "
                "to manage accounts"
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
            "ADMIN_BOOTSTRAPPED",
            {"user_id": admin.id}
        )
        db.commit()
        print("Initial administrator account created.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    create_initial_admin()
