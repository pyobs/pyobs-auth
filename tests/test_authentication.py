import pytest
import responses
from django.contrib.auth.models import User
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from pyobs_auth.authentication import KeycloakAuthentication

from .helpers import register_discovery_and_jwks

factory = APIRequestFactory()


@responses.activate
@pytest.mark.django_db
def test_authenticate_returns_user_and_claims(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="keycloak-sub-1"))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    user, claims = KeycloakAuthentication().authenticate(request)

    assert isinstance(user, User)
    assert user.username == "keycloak-sub-1"
    assert claims["sub"] == "keycloak-sub-1"
    # mint-on-first-login: same sub on a later request resolves to the same local user
    assert User.objects.filter(username="keycloak-sub-1").count() == 1


def test_authenticate_returns_none_without_authorization_header():
    request = factory.get("/")
    assert KeycloakAuthentication().authenticate(request) is None


def test_authenticate_returns_none_for_non_bearer_scheme():
    request = factory.get("/", HTTP_AUTHORIZATION="Token sometoken")
    assert KeycloakAuthentication().authenticate(request) is None


def test_authenticate_raises_on_malformed_header():
    request = factory.get("/", HTTP_AUTHORIZATION="Bearer")
    with pytest.raises(AuthenticationFailed):
        KeycloakAuthentication().authenticate(request)


@responses.activate
@pytest.mark.django_db
def test_authenticate_raises_on_invalid_token(signing_keys, make_claims, monkeypatch):
    from .helpers import generate_signing_keys

    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    other_keys = generate_signing_keys()
    token = other_keys.sign(make_claims())
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with pytest.raises(AuthenticationFailed):
        KeycloakAuthentication().authenticate(request)
