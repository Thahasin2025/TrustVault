from getpass import getpass

from pydantic import EmailStr, TypeAdapter

from backend import models
from backend.audit import create_audit_log
from backend.auth import hash_password
from backend.database import SessionLocal


def reset_admin_password() -> None:
    email = str(TypeAdapter(EmailStr).validate_python(
        input("Administrator email: ").strip()
    ))
    password = getpass("New administrator password (12+ characters): ")
    confirmation = getpass("Confirm new password: ")

    if len(password) < 12:
        raise ValueError("Administrator password must be at least 12 characters")
    if password != confirmation:
        raise ValueError("Passwords do not match")

    db = SessionLocal()
    try:
        admin = db.query(models.User).filter(
            models.User.email == email,
            models.User.role == "admin"
        ).first()
        if not admin:
            raise RuntimeError(
                "No administrator account was found with that email"
            )

        admin.hashed_password = hash_password(password)
        admin.auth_version += 1
        create_audit_log(
            db,
            None,
            None,
            "ADMIN_PASSWORD_RESET",
            {"user_id": admin.id}
        )
        db.commit()
        print("Administrator password reset successfully.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    reset_admin_password()
