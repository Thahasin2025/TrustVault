import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import declarative_base, sessionmaker

load_dotenv()

database_url = URL.create(
    drivername="mysql+pymysql",
    username=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=int(os.getenv("DB_PORT", "3306")),
    database=os.getenv("DB_NAME")
)

# Cloud MySQL (TiDB / Aiven) ki SSL kavali.
# Render lo DB_SSL=true pedithe SSL on avtundi. Local lo em pettakapothe off.
connect_args = {}
if os.getenv("DB_SSL", "false").lower() == "true":
    connect_args = {
        "ssl_ca": "/etc/ssl/certs/ca-certificates.crt",
        "ssl_verify_cert": True,
        "ssl_verify_identity": True,
    }

engine = create_engine(
    database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
    pool_recycle=300,
)

# Base class for database models
Base = declarative_base()

# Create database sessions
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


def test_connection():
    try:
        with engine.connect():
            print("TrustVault connected to MySQL successfully!")
    except Exception as error:
        print("MySQL connection failed:", error)


if __name__ == "__main__":
    test_connection()
