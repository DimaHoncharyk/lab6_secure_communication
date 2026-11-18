import base64
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app, session_storage
from common.aes_service import AesService

client = TestClient(app)
aes_service = AesService()

def create_test_session():
    session_id = "test-" + os.urandom(8).hex()

    aes_key = aes_service.generate_secret_key()
    now = datetime.now(timezone.utc)

    session_storage[session_id] = {
        "aes_key": aes_key,
        "created_at": now,
        "expired_at": now + timedelta(minutes=1),
        "is_valid": True
    }

    return session_id, aes_key

def send_test_message(session_id, aes_key, message, message_hash):
    payload = json.dumps({
        "message": message,
        "hash": message_hash
    })

    iv = base64.b64encode(os.urandom(12)).decode()

    encrypted = aes_service.encrypt(
        {
            "key": aes_key["key"],
            "iv": iv
        },
        payload
    )

    return client.post(
        "/api/messages",
        headers={"x-session-id": session_id},
        json={
            "iv": iv,
            "encrypted_message": encrypted
        }
    )

def test_correct_sha256():
    session_id, aes_key = create_test_session()

    try:
        message = "Testing SHA-256 integrity"

        correct_hash = hashlib.sha256(
            message.encode("utf-8")
        ).hexdigest()

        response = send_test_message(
            session_id,
            aes_key,
            message,
            correct_hash
        )

        assert response.status_code == 200

        data = response.json()
        assert data["session_id"] == session_id

        decrypted_response = aes_service.decrypt(
            {
                "key": aes_key["key"],
                "iv": data["iv"]
            },
            data["encrypted_message"]
        )

        assert f"Original: {message}" in decrypted_response

    finally:
        session_storage.pop(session_id, None)

def test_incorrect_sha256():
    session_id, aes_key = create_test_session()

    try:
        message = "Testing modified message"

        incorrect_hash = hashlib.sha256(
            b"Different message"
        ).hexdigest()

        response = send_test_message(
            session_id,
            aes_key,
            message,
            incorrect_hash
        )

        assert response.status_code == 400
        assert response.json()["detail"] == (
            "Message integrity verification failed"
        )

    finally:
        session_storage.pop(session_id, None)
