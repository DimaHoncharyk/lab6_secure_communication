
import base64
import binascii
import hashlib
import hmac
import json
import os

from datetime import datetime, timezone, timedelta

from cryptography.exceptions import InvalidTag

from fastapi import (
    FastAPI,
    APIRouter,
    Depends,
    Header,
    HTTPException
)

from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.auth import require_access_token
from app.rsa_service import RsaService
from common.aes_service import AesService


# --------------------------------------------------
# FastAPI application
# --------------------------------------------------

app = FastAPI(
    title="Lab 8 Secure Communication API",
    description="Secure Communication API with OpenID Connect",
    version="3.0.0"
)


# --------------------------------------------------
# CORS configuration
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:8080"
    ],
    allow_methods=["GET", "POST"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "x-rsa-id",
        "x-session-id"
    ],
)


# --------------------------------------------------
# Protected API router
# --------------------------------------------------

router = APIRouter(
    dependencies=[Depends(require_access_token)]
)


# --------------------------------------------------
# Cryptographic services
# --------------------------------------------------

rsa_service = RsaService()
aes_service = AesService()


# --------------------------------------------------
# In-memory storage
# --------------------------------------------------

key_storage = {}
session_storage = {}

next_key_id = 1

SESSION_EXPIRE_MINUTES = 1


# --------------------------------------------------
# Request models
# --------------------------------------------------

class SessionRequest(BaseModel):
    encrypted_data: str


class MessageRequest(BaseModel):
    iv: str
    encrypted_message: str


# --------------------------------------------------
# RSA key generation
# --------------------------------------------------

@router.post("/api/crypto-keys/generate/rsa-keys")
def generate_rsa_keys():
    global next_key_id

    try:
        keys = rsa_service.generate_crypto_keys()

        key_id = next_key_id

        key_storage[key_id] = keys

        next_key_id += 1

        return {
            "id": key_id
        }

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="RSA key generation failed"
        )


# --------------------------------------------------
# Get RSA public key
# --------------------------------------------------

@router.get("/api/crypto-keys/rsa-public-key/{id}")
def get_public_key(id: int):

    if id not in key_storage:
        raise HTTPException(
            status_code=404,
            detail="RSA key not found"
        )

    return {
        "public_key": key_storage[id]["public_key"]
    }


# --------------------------------------------------
# Initialize encrypted session
# --------------------------------------------------

@router.post("/api/sessions/init")
def initialize_session(
    request: SessionRequest,
    x_rsa_id: int = Header(...)
):

    if x_rsa_id not in key_storage:
        raise HTTPException(
            status_code=404,
            detail="RSA key not found"
        )

    try:
        private_key = key_storage[x_rsa_id][
            "private_key"
        ]

        decrypted = rsa_service.decrypt(
            private_key,
            request.encrypted_data
        )

        data = json.loads(decrypted)

        session_id = data["session_id"]
        aes_key = data["aes_key"]

        if (
            not isinstance(session_id, str)
            or not session_id
        ):
            raise ValueError("Invalid session ID")

        key_bytes = base64.b64decode(
            aes_key["key"],
            validate=True
        )

        iv_bytes = base64.b64decode(
            aes_key["iv"],
            validate=True
        )

        if (
            len(key_bytes) != 32
            or len(iv_bytes) != 12
        ):
            raise ValueError(
                "Invalid AES key or IV"
            )

        if session_id in session_storage:
            raise ValueError(
                "Session already exists"
            )

        created_at = datetime.now(
            timezone.utc
        )

        expired_at = created_at + timedelta(
            minutes=SESSION_EXPIRE_MINUTES
        )

        session_storage[session_id] = {
            "aes_key": aes_key,
            "created_at": created_at,
            "expired_at": expired_at,
            "is_valid": True
        }

        return {
            "status": "session_created",
            "session_id": session_id,
            "created_at": created_at.isoformat(),
            "expired_at": expired_at.isoformat()
        }

    except (
        ValueError,
        KeyError,
        TypeError,
        binascii.Error,
        json.JSONDecodeError
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid session data"
        )


# --------------------------------------------------
# Send encrypted message
# --------------------------------------------------

@router.post("/api/messages")
def send_message(
    request: MessageRequest,
    x_session_id: str = Header(...)
):

    if x_session_id not in session_storage:
        raise HTTPException(
            status_code=404,
            detail="Session not found"
        )

    session = session_storage[x_session_id]

    current_time = datetime.now(
        timezone.utc
    )

    # Check session expiration

    if (
        current_time >= session["expired_at"]
        or not session["is_valid"]
    ):
        session["is_valid"] = False

        raise HTTPException(
            status_code=440,
            detail="Session expired"
        )

    aes_key = session["aes_key"]

    try:
        # Decrypt incoming message

        message_key = {
            "key": aes_key["key"],
            "iv": request.iv
        }

        decrypted_payload = aes_service.decrypt(
            message_key,
            request.encrypted_message
        )

        # Parse message and SHA-256 hash

        try:
            payload = json.loads(
                decrypted_payload
            )

            original = payload["message"]
            received_hash = payload["hash"]

            if not isinstance(original, str):
                raise ValueError(
                    "Invalid message"
                )

            if not isinstance(received_hash, str):
                raise ValueError(
                    "Invalid hash"
                )

        except (
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError
        ):
            raise HTTPException(
                status_code=400,
                detail="Invalid message payload"
            )

        # Calculate SHA-256

        calculated_hash = hashlib.sha256(
            original.encode("utf-8")
        ).hexdigest()

        # Verify message integrity

        if not hmac.compare_digest(
            calculated_hash,
            received_hash
        ):
            raise HTTPException(
                status_code=400,
                detail=(
                    "Message integrity "
                    "verification failed"
                )
            )

        # Create response

        received_at = datetime.now(
            timezone.utc
        ).isoformat()

        response_text = (
            f"Original: {original}\n"
            f"Received at: {received_at}"
        )

        # Generate new IV

        response_iv = base64.b64encode(
            os.urandom(12)
        ).decode()

        response_key = {
            "key": aes_key["key"],
            "iv": response_iv
        }

        # Encrypt response

        encrypted_response = aes_service.encrypt(
            response_key,
            response_text
        )

        return {
            "session_id": x_session_id,
            "iv": response_iv,
            "encrypted_message": encrypted_response
        }

    except (
        InvalidTag,
        ValueError,
        TypeError,
        KeyError,
        binascii.Error
    ):
        raise HTTPException(
            status_code=400,
            detail="Invalid encrypted message"
        )


# --------------------------------------------------
# Get all sessions
# --------------------------------------------------

@router.get("/api/sessions")
def get_sessions():

    current_time = datetime.now(
        timezone.utc
    )

    sessions = []

    for session_id, session in session_storage.items():

        is_valid = (
            session["is_valid"]
            and current_time < session["expired_at"]
        )

        if not is_valid:
            session["is_valid"] = False

        sessions.append({
            "session_id": session_id,
            "status": (
                "valid" if is_valid else "invalid"
            ),
            "expired_at": session[
                "expired_at"
            ].isoformat()
        })

    return {
        "total": len(sessions),
        "sessions": sessions
    }


# --------------------------------------------------
# Register protected routes
# --------------------------------------------------

app.include_router(router)
