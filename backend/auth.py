from typing import Optional

import os
import jwt
import hashlib
import uuid

from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

# Password security using Argon2
password_hash = PasswordHash.recommended()

# JWT configuration
SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

if not SECRET_KEY:
    raise RuntimeError("JWT_SECRET is missing from .env")


# Hash a password
def hash_password(password: str) -> str:
    return password_hash.hash(password)


# Verify a password
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


# Create an access token
def create_access_token(user_id: int, auth_version: int = 0) -> str:
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE_MINUTES
    )

    payload = {
        "sub": str(user_id),
        "exp": expire,
        "ver": auth_version,
        "jti": uuid.uuid4().hex
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=ALGORITHM
    )

    return token

# Verify and decode an access token
def verify_access_token(token: str):
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )

        user_id = payload.get("sub")

        if user_id is None:
            return None

        return int(user_id)

    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None


def get_access_token_version(token: str) -> Optional[int]:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        version = payload.get("ver", 0)
        if type(version) is not int or version < 0:
            return None
        return version
    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None


def get_access_token_expiration(token: str) -> Optional[datetime]:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        expiration = payload.get("exp")
        if not isinstance(expiration, (int, float)):
            return None
        return datetime.fromtimestamp(expiration, timezone.utc)
    except (jwt.InvalidTokenError, ValueError, TypeError, OverflowError):
        return None


def fingerprint_access_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
