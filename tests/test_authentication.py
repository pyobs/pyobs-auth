import pytest
import responses
from django.conf import settings as django_settings
from django.contrib.auth.models import User
from django.test import override_settings
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
def test_authenticate_defers_for_a_token_from_another_issuer(signing_keys, make_claims, monkeypatch):
    """A well-formed Bearer token that just isn't ours must return None, not raise - so a
    second, unmodifiable Bearer-scheme authenticator stacked after this one still gets a turn."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(iss="https://someone-elses-keycloak.example.org/realms/x"))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    assert KeycloakAuthentication().authenticate(request) is None


@responses.activate
@pytest.mark.django_db
def test_authenticate_allows_inactive_user_by_default(signing_keys, make_claims, monkeypatch):
    """Default behavior: is_active is not the authorization gate any more (claims are, via
    REQUIRED_GROUPS/REQUIRED_ROLES) - ENFORCE_LOCAL_ACTIVE must be set to keep the old gate."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    User.objects.create(username="inactive-sub", is_active=False)
    token = signing_keys.sign(make_claims(sub="inactive-sub"))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    user, claims = KeycloakAuthentication().authenticate(request)
    assert user.username == "inactive-sub"


@responses.activate
@pytest.mark.django_db
def test_authenticate_raises_for_inactive_user_with_enforce_local_active(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    User.objects.create(username="inactive-sub", is_active=False)
    token = signing_keys.sign(make_claims(sub="inactive-sub"))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "ENFORCE_LOCAL_ACTIVE": True}):
        with pytest.raises(AuthenticationFailed):
            KeycloakAuthentication().authenticate(request)


@responses.activate
@pytest.mark.django_db
def test_authenticate_raises_when_required_group_missing(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="archive-sub", groups=["/some-other-group"]))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive"]}):
        with pytest.raises(AuthenticationFailed):
            KeycloakAuthentication().authenticate(request)


@responses.activate
@pytest.mark.django_db
def test_authenticate_passes_when_required_group_present(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="archive-sub", groups=["/pyobs-archive"]))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive"]}):
        user, claims = KeycloakAuthentication().authenticate(request)
    assert user.username == "archive-sub"


@responses.activate
@pytest.mark.django_db
def test_authenticate_does_not_mint_a_user_when_required_group_missing(signing_keys, make_claims, monkeypatch):
    """authorize() must run before USER_RESOLVER - an unauthorized caller shouldn't get a local
    User row minted just by presenting a validly-signed-but-ungrouped token."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="never-minted-sub", groups=[]))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive"]}):
        with pytest.raises(AuthenticationFailed):
            KeycloakAuthentication().authenticate(request)

    assert not User.objects.filter(username="never-minted-sub").exists()


@responses.activate
@pytest.mark.django_db
def test_authenticate_propagates_malformed_required_roles_loudly(signing_keys, make_claims, monkeypatch):
    """A malformed REQUIRED_ROLES entry is a deployment config error, not user input - it must
    surface loudly (ValueError, ultimately a 500), not be swallowed into a quiet refusal."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="whatever"))
    request = factory.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "REQUIRED_ROLES": ["no-colon-here"]}):
        with pytest.raises(ValueError, match="malformed"):
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
