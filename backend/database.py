
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine import URL, make_url
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

if os.getenv("DATABASE_URL"):
    parsed_url = make_url(os.environ["DATABASE_URL"])
    if parsed_url.get_backend_name() == "postgresql":
        parsed_url = parsed_url.set(drivername="postgresql+psycopg2")
    engine = create_engine(parsed_url, pool_pre_ping=True)
elif os.getenv("TRUSTVAULT_DEMO") == "1":
    engine = create_engine("sqlite:////tmp/trustvault-demo.sqlite", connect_args={"check_same_thread": False})
else:
    engine = create_engine(database_url)

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
