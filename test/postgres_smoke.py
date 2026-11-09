"""Exercise the deployment against an explicitly supplied, disposable database."""
import os
import uuid

assert os.environ.get("TRUSTVAULT_DISPOSABLE_DB") == "1"
from fastapi.testclient import TestClient
from backend.database import Base, engine
from backend.main import app

Base.metadata.create_all(engine)
suffix = uuid.uuid4().hex[:12]
with TestClient(app) as client:
    def register(role):
        email = f"{role}-{suffix}@example.com"
        response = client.post("/register", json={"full_name": f"Test {role}", "email": email,
                                                   "password": "Password123!", "role": role})
        assert response.status_code in (200, 201), response.text
        response = client.post("/login", json={"email": email, "password": "Password123!"})
        assert response.status_code == 200, response.text
        return {"Authorization": "Bearer " + response.json()["access_token"]}

    owner, viewer = register("owner"), register("viewer")
    for _ in range(4):
        response = client.get("/me", headers=owner)
        assert response.status_code == 200, response.text
    upload = client.post("/documents/upload", headers=owner, data={"category": "test"},
                         files={"file": ("example.txt", b"persistent sample", "text/plain")})
    assert upload.status_code == 200, upload.text
    document_id = upload.json()["document_id"]
    response = client.get(f"/documents/{document_id}/view", headers=owner)
    assert response.status_code == 200 and response.content == b"persistent sample", response.text
    print("PostgreSQL registration, login, repeated session checks, upload and view passed")
