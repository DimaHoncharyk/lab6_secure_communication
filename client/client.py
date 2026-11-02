import base64
import json
import os
import sys
import uuid

import requests

from app.rsa_service import RsaService
from common.aes_service import AesService


SERVER_URL = "http://127.0.0.1:8000"


def main():
    rsa_service = RsaService()
    aes_service = AesService()

    print("=== Secure Communication Client ===")

    try:
        # 1. Generate RSA keys on the server
        response = requests.post(
            f"{SERVER_URL}/api/crypto-keys/generate/rsa-keys",
            timeout=10
        )
        response.raise_for_status()
        rsa_id = response.json()["id"]

        # 2. Get the server's public RSA key
        response = requests.get(
            f"{SERVER_URL}/api/crypto-keys/rsa-public-key/{rsa_id}",
            timeout=10
        )
        response.raise_for_status()
        public_key = response.json()["public_key"]

        # 3. Generate AES key and session ID
        aes_key = aes_service.generate_secret_key()
        session_id = str(uuid.uuid4())

        # 4. Encrypt session information with RSA
        session_data = json.dumps({
            "session_id": session_id,
            "aes_key": aes_key
        })

        encrypted_session = rsa_service.encrypt(
            public_key,
            session_data
        )

        # 5. Establish secure session
        response = requests.post(
            f"{SERVER_URL}/api/sessions/init",
            headers={"x-rsa-id": str(rsa_id)},
            json={"encrypted_data": encrypted_session},
            timeout=10
        )
        response.raise_for_status()

        print("Secure session established!")
        print("Session ID:", session_id)

        # 6. Interactive message exchange
        while True:
            message = input("\nEnter message (exit to quit): ")

            if message.lower() == "exit":
                print("Client stopped.")
                break

            if not message.strip():
                continue

            # New IV for every message
            request_iv = base64.b64encode(
                os.urandom(12)
            ).decode()

            message_key = {
                "key": aes_key["key"],
                "iv": request_iv
            }

            encrypted_message = aes_service.encrypt(
                message_key,
                message
            )

            print("Encrypted:", encrypted_message)

            # Send encrypted data
            response = requests.post(
                f"{SERVER_URL}/api/messages",
                headers={"x-session-id": session_id},
                json={
                    "iv": request_iv,
                    "encrypted_message": encrypted_message
                },
                timeout=10
            )
            response.raise_for_status()

            data = response.json()

            # Decrypt server response
            response_key = {
                "key": aes_key["key"],
                "iv": data["iv"]
            }

            decrypted = aes_service.decrypt(
                response_key,
                data["encrypted_message"]
            )

            print("\nServer response:")
            print(decrypted)
            print("Session:", data["session_id"])

    except requests.RequestException as error:
        print("Server communication error:", error)
        sys.exit(1)

    except (ValueError, KeyError) as error:
        print("Invalid response or encryption data:", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
