import os
import sys

import requests
from dotenv import load_dotenv


load_dotenv()

KEYCLOAK_URL = os.getenv(
    "KEYCLOAK_URL",
    "http://localhost:8081"
)

REALM = "oidc-lab"

CLIENT_ID = os.getenv(
    "KEYCLOAK_CLIENT_ID",
    "lab-cli"
)

CLIENT_SECRET = os.getenv(
    "KEYCLOAK_CLIENT_SECRET"
)

API_URL = os.getenv(
    "API_URL",
    "http://127.0.0.1:8000"
)


def get_access_token():
    """
    Obtain JWT using OAuth 2.0 Client Credentials.
    """

    token_url = (
        f"{KEYCLOAK_URL}/realms/{REALM}"
        "/protocol/openid-connect/token"
    )

    print("[1] Requesting access token from Keycloak...")

    if not CLIENT_SECRET:
        raise ValueError(
            "KEYCLOAK_CLIENT_SECRET is missing in .env"
        )

    response = requests.post(
        token_url,
        data={
            "grant_type": "client_credentials",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET
        },
        timeout=15
    )

    response.raise_for_status()

    token_data = response.json()

    access_token = token_data["access_token"]

    print("Access token received successfully!")
    print(
        "Token type:",
        token_data.get("token_type")
    )
    print(
        "Expires in:",
        token_data.get("expires_in"),
        "seconds"
    )

    return access_token


def call_protected_api(access_token):
    """
    Call protected FastAPI endpoint.
    """

    endpoint = f"{API_URL}/api/sessions"

    print("\n[2] Calling protected FastAPI endpoint...")

    response = requests.get(
        endpoint,
        headers={
            "Authorization": f"Bearer {access_token}"
        },
        timeout=15
    )

    print("HTTP status:", response.status_code)

    try:
        print("Server response:")
        print(response.json())
    except ValueError:
        print(response.text)

    response.raise_for_status()


def test_without_token():
    """
    Confirm that the API rejects missing tokens.
    """

    print("\n[3] Testing request without token...")

    response = requests.get(
        f"{API_URL}/api/sessions",
        timeout=15
    )

    print("HTTP status:", response.status_code)
    print("Response:", response.text)

    assert response.status_code == 401


def main():
    print("=== Lab 8 OIDC Console Client ===")
    print("Authorization: Client Credentials\n")

    try:
        token = get_access_token()

        call_protected_api(token)

        test_without_token()

        print("\nAll checks completed successfully!")

    except (
        requests.RequestException,
        ValueError,
        KeyError,
        AssertionError
    ) as error:
        print("\nError:", error)
        sys.exit(1)


if __name__ == "__main__":
    main()
