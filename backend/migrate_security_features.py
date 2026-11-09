from sqlalchemy import inspect, text

from backend.audit import initialize_audit_anchor
from backend.database import Base, SessionLocal, engine


def migrate_security_features() -> None:
    if engine.dialect.name != "mysql":
        raise RuntimeError(
            "This migration is intended for the configured MySQL database"
        )

    Base.metadata.create_all(bind=engine)
    inspector = inspect(engine)

    user_columns = {
        column["name"] for column in inspector.get_columns("users")
    }
    permission_columns = {
        column["name"]
        for column in inspector.get_columns("document_permissions")
    }
    document_columns = {
        column["name"]
        for column in inspector.get_columns("documents")
    }
    verification_columns = {
        column["name"]
        for column in inspector.get_columns("audit_verifications")
    }

    with engine.begin() as connection:
        if "is_active" not in user_columns:
            connection.execute(text(
                "ALTER TABLE users "
                "ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE"
            ))

        if "auth_version" not in user_columns:
            connection.execute(text(
                "ALTER TABLE users "
                "ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0"
            ))

        if "can_download" not in permission_columns:
            connection.execute(text(
                "ALTER TABLE document_permissions "
                "ADD COLUMN can_download BOOLEAN NOT NULL DEFAULT FALSE"
            ))

        if "purged_at" not in document_columns:
            connection.execute(text(
                "ALTER TABLE documents ADD COLUMN purged_at DATETIME NULL"
            ))

        if "details" not in verification_columns:
            connection.execute(text(
                "ALTER TABLE audit_verifications "
                "ADD COLUMN details JSON NULL"
            ))

    inspector = inspect(engine)
    unique_pairs = {
        tuple(constraint["column_names"])
        for constraint in inspector.get_unique_constraints(
            "document_permissions"
        )
    }
    unique_pairs.update(
        tuple(index["column_names"])
        for index in inspector.get_indexes("document_permissions")
        if index.get("unique")
    )

    with engine.begin() as connection:
        duplicate = connection.execute(text(
            "SELECT document_id, user_id, COUNT(*) AS row_count "
            "FROM document_permissions "
            "GROUP BY document_id, user_id "
            "HAVING COUNT(*) > 1 "
            "LIMIT 1"
        )).first()
        if duplicate:
            raise RuntimeError(
                "Duplicate permission rows must be resolved before migration "
                f"(document_id={duplicate.document_id}, "
                f"user_id={duplicate.user_id})"
            )

        if ("document_id", "user_id") not in unique_pairs:
            connection.execute(text(
                "CREATE UNIQUE INDEX uq_document_permission_user "
                "ON document_permissions (document_id, user_id)"
            ))

    db = SessionLocal()
    try:
        try:
            initialize_audit_anchor(db)
        except RuntimeError as error:
            print(
                "WARNING: Schema changes were applied, but the audit "
                f"anchor was not initialized: {error}"
            )
            print(
                "Do not treat the existing audit history as verified; "
                "investigate it before enabling audit-integrity claims."
            )
    finally:
        db.close()

    print("TrustVault security schema migration completed.")


if __name__ == "__main__":
    migrate_security_features()
