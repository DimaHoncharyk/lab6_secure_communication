import base64
import binascii
import json
import os
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel

from app.rsa_service import RsaService
from common.aes_service import AesService


app = FastAPI(
    title="Lab 6 Secure Communication API",
    version="1.0.0"
)

rsa_service = RsaService()
aes_service = AesService()

key_storage = {}
session_storage = {}
next_key_id = 1


class SessionRequest(BaseModel):
    encrypted_data: str


class MessageRequest(BaseModel):
    iv: str
    encrypted_message: str


@app.post("/api/crypto-keys/generate/rsa-keys")
def generate_rsa_keys():
    global next_key_id

    try:
        keys = rsa_service.generate_crypto_keys()
        key_id = next_key_id
        key_storage[key_id] = keys
        next_key_id += 1
        return {"id": key_id}
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="RSA key generation failed"
        )


@app.get("/api/crypto-keys/rsa-public-key/{id}")
def get_public_key(id: int):
    if id not in key_storage:
        raise HTTPException(
            status_code=404,
            detail="RSA key not found"
        )

    return {
        "public_key": key_storage[id]["public_key"]
    }


@app.post("/api/sessions/init")
def initialize_session(
    request: SessionRequest,
    x_rsa_id: int = Header(...)
):
    if x_rsa_id not in key_storage:
        raise HTTPException(404, "RSA key not found")

    try:
        private_key = key_storage[x_rsa_id]["private_key"]

        decrypted = rsa_service.decrypt(
            private_key,
            request.encrypted_data
        )

        data = json.loads(decrypted)
        session_id = data["session_id"]
        aes_key = data["aes_key"]

        if not isinstance(session_id, str) or not session_id:
            raise ValueError("Invalid session ID")

        key_bytes = base64.b64decode(
            aes_key["key"], validate=True
        )
        iv_bytes = base64.b64decode(
            aes_key["iv"], validate=True
        )

        if len(key_bytes) != 32 or len(iv_bytes) != 12:
            raise ValueError("Invalid AES key or IV")

        if session_id in session_storage:
            raise ValueError("Session already exists")

        session_storage[session_id] = aes_key

        return {
            "status": "session_created",
            "session_id": session_id
        }

    except (ValueError, KeyError, TypeError, binascii.Error, json.JSONDecodeError):
        raise HTTPException(400, "Invalid session data")


@app.post("/api/messages")
def send_message(
    request: MessageRequest,
    x_session_id: str = Header(...)
):
    if x_session_id not in session_storage:
        raise HTTPException(404, "Session not found")

    aes_key = session_storage[x_session_id]

    try:
        message_key = {
            "key": aes_key["key"],
            "iv": request.iv
        }

        original = aes_service.decrypt(
            message_key,
            request.encrypted_message
        )

        received_at = datetime.now(timezone.utc).isoformat()

        response_text = (
            f"Original: {original}\n"
            f"Received at: {received_at}"
        )

        response_iv = base64.b64encode(
            os.urandom(12)
        ).decode()

        response_key = {
            "key": aes_key["key"],
            "iv": response_iv
        }

        encrypted_response = aes_service.encrypt(
            response_key,
            response_text
        )

        return {
            "session_id": x_session_id,
            "iv": response_iv,
            "encrypted_message": encrypted_response
        }

    except (InvalidTag, ValueError, TypeError, KeyError, binascii.Error):
        raise HTTPException(400, "Invalid encrypted message")
