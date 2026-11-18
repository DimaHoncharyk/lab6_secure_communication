import pytest

from app.main import app
from app.auth import require_access_token


@pytest.fixture(autouse=True)
def mock_jwt_auth():
    """
    Replace JWT verification only during unit tests.
    Production API remains protected.
    """

    def fake_auth():
        return {
            "sub": "test-user",
            "iss": "http://localhost:8081/realms/oidc-lab",
            "aud": ["lab-api"],
            "azp": "lab-spa"
        }

    app.dependency_overrides[require_access_token] = fake_auth

    yield

    app.dependency_overrides.pop(
        require_access_token,
        None
    )
