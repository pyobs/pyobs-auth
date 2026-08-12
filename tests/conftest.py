from __future__ import annotations

import time

import pytest

from pyobs_auth.discovery import clear_discovery_cache
from pyobs_auth.settings import KeycloakSettings
from pyobs_auth.validation import clear_jwk_client_cache

from .helpers import generate_signing_keys


@pytest.fixture(autouse=True)
def _clear_module_caches():
    clear_discovery_cache()
    clear_jwk_client_cache()
    yield
    clear_discovery_cache()
    clear_jwk_client_cache()


@pytest.fixture
def keycloak_settings() -> KeycloakSettings:
    return KeycloakSettings(
        server_url="https://keycloak.example.org",
        realm="pyobs",
        client_id="archive",
        client_secret="test-secret",
        redirect_uri="https://archive.example.org/accounts/keycloak/callback/",
        user_resolver="tests.helpers.resolve_user",
    )


@pytest.fixture
def signing_keys():
    return generate_signing_keys()


@pytest.fixture
def make_claims(keycloak_settings):
    def _make(**overrides):
        now = int(time.time())
        claims = {
            "iss": "https://keycloak.example.org/realms/pyobs",
            "aud": keycloak_settings.client_id,
            "sub": "abc-123",
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return claims

    return _make
