import time
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, override_settings

from .helpers import TOKEN_ENDPOINT, register_discovery_and_jwks


def _login(client, signing_keys, make_claims, sub, *, groups=None, refresh_token="rt-1"):
    claims = make_claims(sub=sub, **({"groups": groups} if groups is not None else {}))
    token = signing_keys.sign(claims)
    responses.post(TOKEN_ENDPOINT, json={"access_token": token, "refresh_token": refresh_token})

    login_response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]
    client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")
    return claims


def _expire_session(client):
    session = client.session
    session["pyobs_auth_access_token_exp"] = time.time() - 10
    session.save()


def _token_endpoint_call_count():
    # Middleware only ever talks to Keycloak via a POST to the token endpoint (refresh) - unlike
    # a raw responses.calls count, this isn't perturbed by LoginView's own (cached) discovery GET.
    return sum(
        1 for call in responses.calls if call.request.method == "POST" and call.request.url.startswith(TOKEN_ENDPOINT)
    )


@responses.activate
@pytest.mark.django_db
def test_fresh_session_makes_no_refresh_call(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, "sub-1")
    calls_before = _token_endpoint_call_count()

    client.get("/accounts/keycloak/login/")

    assert _token_endpoint_call_count() == calls_before


@responses.activate
@pytest.mark.django_db
def test_expired_session_refreshes_and_updates_session(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, "sub-1")
    _expire_session(client)

    new_claims = make_claims(sub="sub-1", exp=int(time.time()) + 999)
    new_token = signing_keys.sign(new_claims)
    responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "rt-2"})

    client.get("/accounts/keycloak/login/")

    assert client.session["pyobs_auth_access_token_exp"] == new_claims["exp"]
    assert client.session["pyobs_auth_refresh_token"] == "rt-2"
    assert client.session["_auth_user_id"] == str(User.objects.get(username="sub-1").pk)


@responses.activate
@pytest.mark.django_db
def test_refresh_failure_logs_out(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, "sub-1")
    _expire_session(client)

    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})

    client.get("/accounts/keycloak/login/")

    assert "_auth_user_id" not in client.session
    assert "pyobs_auth_refresh_token" not in client.session


@responses.activate
@pytest.mark.django_db
def test_refresh_succeeds_but_revoked_group_logs_out(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(PYOBS_AUTH={**settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive"]}):
        _login(client, signing_keys, make_claims, "sub-1", groups=["/pyobs-archive"])
        _expire_session(client)

        # refreshed token no longer carries the required group - simulates revocation in Keycloak
        new_claims = make_claims(sub="sub-1", exp=int(time.time()) + 999, groups=[])
        new_token = signing_keys.sign(new_claims)
        responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "rt-2"})

        client.get("/accounts/keycloak/login/")

    assert "_auth_user_id" not in client.session


@responses.activate
@pytest.mark.django_db
def test_local_password_session_is_untouched(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    user = User.objects.create_user(username="localuser", password="pw")
    client = Client()
    client.force_login(user)
    calls_before = _token_endpoint_call_count()

    client.get("/accounts/keycloak/login/")

    assert _token_endpoint_call_count() == calls_before
    assert client.session["_auth_user_id"] == str(user.pk)
