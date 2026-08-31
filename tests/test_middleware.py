from __future__ import annotations

import time
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from django.conf import settings as django_settings
from django.contrib.auth.models import User
from django.test import Client, override_settings

from .helpers import TOKEN_ENDPOINT, register_discovery_and_jwks


def _login(client: Client, signing_keys, make_claims, *, sub: str, with_refresh_token: bool = True, **claim_overrides):
    claims = make_claims(sub=sub, **claim_overrides)
    token = signing_keys.sign(claims)
    token_response = {"access_token": token}
    if with_refresh_token:
        token_response["refresh_token"] = "initial-refresh-token"
    responses.post(TOKEN_ENDPOINT, json=token_response)

    login_response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]
    client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")
    return claims


def _expire_session(client: Client) -> None:
    session = client.session
    session["pyobs_auth_access_expires"] = int(time.time()) - 10
    session.save()


@responses.activate
@pytest.mark.django_db
def test_noop_when_session_has_no_refresh_token(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-1", with_refresh_token=False)
    assert "pyobs_auth_refresh_token" not in client.session
    calls_before = len(responses.calls)

    client.get("/")

    assert len(responses.calls) == calls_before
    assert "_auth_user_id" in client.session


@responses.activate
@pytest.mark.django_db
def test_noop_when_access_token_not_yet_expired(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    claims = _login(client, signing_keys, make_claims, sub="sub-2")
    calls_before = len(responses.calls)

    client.get("/")

    assert len(responses.calls) == calls_before
    assert client.session["pyobs_auth_access_expires"] == claims["exp"]
    assert "_auth_user_id" in client.session


@responses.activate
@pytest.mark.django_db
def test_expired_and_successful_refresh_updates_session_and_keeps_user_logged_in(
    signing_keys, make_claims, monkeypatch
):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-3")
    _expire_session(client)

    new_claims = make_claims(sub="sub-3")
    new_token = signing_keys.sign(new_claims)
    responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "refreshed-token"})

    client.get("/")

    assert "_auth_user_id" in client.session
    assert client.session["pyobs_auth_access_expires"] == new_claims["exp"]
    assert client.session["pyobs_auth_refresh_token"] == "refreshed-token"


@responses.activate
@pytest.mark.django_db
def test_expired_and_refresh_call_fails_logs_out(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-4")
    _expire_session(client)

    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})

    client.get("/")

    assert "_auth_user_id" not in client.session


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_with_invalid_token_response_logs_out(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-4b")
    _expire_session(client)

    # 200 but no access_token in the body
    responses.post(TOKEN_ENDPOINT, json={"refresh_token": "whatever"})

    client.get("/")

    assert "_auth_user_id" not in client.session


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_succeeds_but_authorization_now_fails_logs_out(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive"]}):
        _login(client, signing_keys, make_claims, sub="sub-5", groups=["/pyobs-archive"])
        assert "_auth_user_id" in client.session
        _expire_session(client)

        # revoked between requests: refreshed token no longer carries the required group
        new_claims = make_claims(sub="sub-5", groups=[])
        new_token = signing_keys.sign(new_claims)
        responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "refreshed-token"})

        client.get("/")

    assert "_auth_user_id" not in client.session


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_network_error_does_not_log_out(signing_keys, make_claims, monkeypatch):
    """A Keycloak outage (or any non-invalid_grant failure) at token-expiry must not mass-log-out
    active sessions - only a genuinely revoked/expired grant should."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-7")
    _expire_session(client)
    stale_expiry = client.session["pyobs_auth_access_expires"]

    responses.post(TOKEN_ENDPOINT, status=503, body="Service Unavailable")

    client.get("/")

    assert "_auth_user_id" in client.session
    # left as-is (still stale/expired) so the next request retries the refresh
    assert client.session["pyobs_auth_access_expires"] == stale_expiry
    assert client.session["pyobs_auth_refresh_token"] == "initial-refresh-token"


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_with_error_other_than_invalid_grant_does_not_log_out(
    signing_keys, make_claims, monkeypatch
):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-7b")
    _expire_session(client)

    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "temporarily_unavailable"})

    client.get("/")

    assert "_auth_user_id" in client.session


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_invalid_grant_race_adopts_concurrently_refreshed_session(
    signing_keys, make_claims, monkeypatch
):
    """Two requests can both see the access token as expired and both try to refresh - if the
    realm rotates refresh tokens, the loser gets invalid_grant even though nothing was actually
    revoked. Simulated here by updating the session store directly (standing in for "a concurrent
    request already completed its own refresh") before the middleware's own refresh call fails."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-8")
    _expire_session(client)

    # Simulate the winning concurrent request: write a fresh, non-expired state directly to the
    # session store (not through this `client`, so `client.session` stays the stale in-memory copy).
    from importlib import import_module

    from django.conf import settings as django_settings

    engine = import_module(django_settings.SESSION_ENGINE)
    store = engine.SessionStore(session_key=client.session.session_key)
    future_expiry = int(time.time()) + 300
    store["pyobs_auth_access_expires"] = future_expiry
    store["pyobs_auth_refresh_token"] = "winner-refresh-token"
    store.save()

    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})

    client.get("/")

    assert "_auth_user_id" in client.session
    assert client.session["pyobs_auth_access_expires"] == future_expiry
    assert client.session["pyobs_auth_refresh_token"] == "winner-refresh-token"


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_invalid_grant_without_a_winning_concurrent_refresh_logs_out(
    signing_keys, make_claims, monkeypatch
):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-8b")
    _expire_session(client)

    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})

    client.get("/")

    assert "_auth_user_id" not in client.session


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_resolver_rejection_logs_out(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(
        PYOBS_AUTH={**django_settings.PYOBS_AUTH, "USER_RESOLVER": "tests.helpers.resolve_user_or_reject"}
    ):
        _login(client, signing_keys, make_claims, sub="sub-9")
        assert "_auth_user_id" in client.session
        _expire_session(client)

        new_claims = make_claims(sub="sub-9", email="reject@example.org")
        new_token = signing_keys.sign(new_claims)
        responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "refreshed-token"})

        client.get("/")

    assert "_auth_user_id" not in client.session


@responses.activate
@pytest.mark.django_db
def test_refresh_updates_request_user_within_the_same_request(signing_keys, make_claims, monkeypatch):
    """The middleware must not only update the session for the *next* request - the resolver's
    freshly-synced user (e.g. a claim-derived is_superuser flip) has to be visible to the request
    that triggered the refresh too. The test app has no view that echoes request.user back, so
    this drives the middleware's hook directly against a real session built the same way
    SessionMiddleware would."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    _login(client, signing_keys, make_claims, sub="sub-10")
    _expire_session(client)

    new_claims = make_claims(sub="sub-10")
    new_token = signing_keys.sign(new_claims)
    responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "refreshed-token"})

    from importlib import import_module

    from django.conf import settings as django_settings
    from django.contrib.auth.models import AnonymousUser
    from django.test import RequestFactory

    from pyobs_auth.middleware import KeycloakSessionRefreshMiddleware

    engine = import_module(django_settings.SESSION_ENGINE)
    request = RequestFactory().get("/")
    request.session = engine.SessionStore(session_key=client.session.session_key)
    request.user = AnonymousUser()  # stale on purpose - must be replaced by the refresh

    KeycloakSessionRefreshMiddleware(lambda r: None)._maybe_refresh(request)

    assert request.user.is_authenticated
    assert request.user.username == "sub-10"


@responses.activate
@pytest.mark.django_db
def test_expired_refresh_with_enforce_local_active_and_user_deactivated_logs_out(
    signing_keys, make_claims, monkeypatch
):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(PYOBS_AUTH={**django_settings.PYOBS_AUTH, "ENFORCE_LOCAL_ACTIVE": True}):
        _login(client, signing_keys, make_claims, sub="sub-6")
        assert "_auth_user_id" in client.session
        _expire_session(client)

        User.objects.filter(username="sub-6").update(is_active=False)

        new_claims = make_claims(sub="sub-6")
        new_token = signing_keys.sign(new_claims)
        responses.post(TOKEN_ENDPOINT, json={"access_token": new_token, "refresh_token": "refreshed-token"})

        client.get("/")

    assert "_auth_user_id" not in client.session
