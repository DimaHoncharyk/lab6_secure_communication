import os

import jwt
from jwt import PyJWKClient, PyJWKClientError
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


KEYCLOAK_ISSUER = os.getenv(
    "KEYCLOAK_ISSUER",
    "http://localhost:8081/realms/oidc-lab"
)

KEYCLOAK_JWKS_URL = os.getenv(
    "KEYCLOAK_JWKS_URL",
    f"{KEYCLOAK_ISSUER}/protocol/openid-connect/certs"
)

API_AUDIENCE = "lab-api"

bearer_scheme = HTTPBearer(auto_error=False)

jwks_client = PyJWKClient(
    KEYCLOAK_JWKS_URL,
    timeout=5
)


def require_access_token(
    credentials: HTTPAuthorizationCredentials | None = Depends(
        bearer_scheme
    )
):
    if credentials is None:
        raise HTTPException(
            status_code=401,
            detail="Missing Bearer access token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    token = credentials.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=API_AUDIENCE,
            issuer=KEYCLOAK_ISSUER,
            options={
                "require": ["exp", "iat", "iss", "aud"]
            }
        )

        if not payload.get("sub"):
            raise jwt.InvalidTokenError("Missing subject")

        return payload

    except jwt.ExpiredSignatureError:
        detail = "Access token expired"

    except (jwt.PyJWTError, PyJWKClientError):
        detail = "Invalid access token"

    raise HTTPException(
        status_code=401,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"}
    )
