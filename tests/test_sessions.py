from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app, session_storage
from common.aes_service import AesService


client = TestClient(app)
aes_service = AesService()


def create_session(expired=False):
    session_id = str(uuid4())
    now = datetime.now(timezone.utc)

    expired_at = (
        now - timedelta(minutes=1)
        if expired
        else now + timedelta(minutes=1)
    )

    session_storage[session_id] = {
        "aes_key": aes_service.generate_secret_key(),
        "created_at": now,
        "expired_at": expired_at,
        "is_valid": True
    }

    return session_id


def test_valid_session():
    session_id = create_session()

    try:
        response = client.get("/api/sessions")

        assert response.status_code == 200

        sessions = response.json()["sessions"]

        session = next(
            s for s in sessions
            if s["session_id"] == session_id
        )

        assert session["status"] == "valid"
        assert "expired_at" in session

    finally:
        session_storage.pop(session_id, None)


def test_expired_session():
    session_id = create_session(expired=True)

    try:
        response = client.get("/api/sessions")

        assert response.status_code == 200

        sessions = response.json()["sessions"]

        session = next(
            s for s in sessions
            if s["session_id"] == session_id
        )

        assert session["status"] == "invalid"
        assert session_storage[session_id]["is_valid"] is False

    finally:
        session_storage.pop(session_id, None)
