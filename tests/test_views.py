from urllib.parse import parse_qs, urlparse

import pytest
import responses
from django.conf import settings
from django.contrib.auth.models import User
from django.test import Client, override_settings

from .helpers import END_SESSION_ENDPOINT, TOKEN_ENDPOINT, register_discovery_and_jwks


@responses.activate
@pytest.mark.django_db
def test_login_view_redirects_to_keycloak_and_stores_session_state(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    response = client.get("/accounts/keycloak/login/?next=/dashboard/")

    assert response.status_code == 302
    query = parse_qs(urlparse(response.url).query)
    assert query["client_id"] == ["archive"]
    session = client.session
    assert session["pyobs_auth_state"] == query["state"][0]
    assert session["pyobs_auth_next"] == "/dashboard/"


@responses.activate
@pytest.mark.django_db
def test_login_view_defaults_next_to_root_when_missing_or_empty(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    client.get("/accounts/keycloak/login/")
    assert client.session["pyobs_auth_next"] == "/"

    client.get("/accounts/keycloak/login/?next=")
    assert client.session["pyobs_auth_next"] == "/"


@responses.activate
@pytest.mark.django_db
def test_full_login_flow(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="keycloak-sub-42"))
    responses.post(TOKEN_ENDPOINT, json={"access_token": token})

    client = Client()
    login_response = client.get("/accounts/keycloak/login/?next=/dashboard/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]

    callback_response = client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")

    assert callback_response.status_code == 302
    assert callback_response.url == "/dashboard/"
    assert User.objects.filter(username="keycloak-sub-42").exists()
    # user should now be logged into the session
    assert client.session["_auth_user_id"] == str(User.objects.get(username="keycloak-sub-42").pk)


@responses.activate
@pytest.mark.django_db
def test_callback_allows_inactive_user_by_default(signing_keys, make_claims, monkeypatch):
    """Default behavior: is_active is not the authorization gate any more - ENFORCE_LOCAL_ACTIVE
    must be set to keep the old "pending activation" gate."""
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    User.objects.create(username="inactive-sub", is_active=False)
    token = signing_keys.sign(make_claims(sub="inactive-sub"))
    responses.post(TOKEN_ENDPOINT, json={"access_token": token})

    client = Client()
    login_response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]

    response = client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")

    assert response.status_code == 302
    assert client.session["_auth_user_id"] == str(User.objects.get(username="inactive-sub").pk)


@responses.activate
@pytest.mark.django_db
def test_callback_rejects_inactive_user_with_enforce_local_active(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    User.objects.create(username="inactive-sub", is_active=False)
    token = signing_keys.sign(make_claims(sub="inactive-sub"))
    responses.post(TOKEN_ENDPOINT, json={"access_token": token})

    client = Client()
    with override_settings(PYOBS_AUTH={**settings.PYOBS_AUTH, "ENFORCE_LOCAL_ACTIVE": True}):
        login_response = client.get("/accounts/keycloak/login/")
        state = parse_qs(urlparse(login_response.url).query)["state"][0]

        response = client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")

    assert response.status_code == 400
    assert "_auth_user_id" not in client.session
    # a styled error page, not a bare-text 400 - see pyobs_auth/templates/pyobs_auth/error.html
    assert b"pending activation" in response.content
    assert b'href="/"' in response.content


@responses.activate
@pytest.mark.django_db
def test_callback_rejects_user_without_required_group(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="ungrouped-sub", groups=["/some-other-group"]))
    responses.post(TOKEN_ENDPOINT, json={"access_token": token})

    client = Client()
    with override_settings(PYOBS_AUTH={**settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive"]}):
        login_response = client.get("/accounts/keycloak/login/")
        state = parse_qs(urlparse(login_response.url).query)["state"][0]

        response = client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")

    assert response.status_code == 400
    assert "_auth_user_id" not in client.session
    assert b"not authorized" in response.content


@responses.activate
@pytest.mark.django_db
def test_callback_stores_refresh_token_and_access_expiry(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    claims = make_claims(sub="keycloak-sub-1")
    token = signing_keys.sign(claims)
    responses.post(TOKEN_ENDPOINT, json={"access_token": token, "refresh_token": "the-refresh-token"})

    client = Client()
    login_response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]
    client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")

    assert client.session["pyobs_auth_refresh_token"] == "the-refresh-token"
    assert client.session["pyobs_auth_access_expires"] == claims["exp"]


@responses.activate
@pytest.mark.django_db
def test_callback_does_not_store_refresh_token_when_absent(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="keycloak-sub-1"))
    responses.post(TOKEN_ENDPOINT, json={"access_token": token})

    client = Client()
    login_response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]
    client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")

    assert "pyobs_auth_refresh_token" not in client.session
    assert "pyobs_auth_access_expires" not in client.session


@responses.activate
@pytest.mark.django_db
def test_callback_rejects_mismatched_state(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    client.get("/accounts/keycloak/login/")  # populate a real state we then ignore

    response = client.get("/accounts/keycloak/callback/?code=x&state=not-the-real-state")

    assert response.status_code == 400


@responses.activate
@pytest.mark.django_db
def test_callback_rejects_missing_code(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()
    response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(response.url).query)["state"][0]

    response = client.get(f"/accounts/keycloak/callback/?state={state}")

    assert response.status_code == 400


def test_callback_surfaces_keycloak_error():
    client = Client()
    response = client.get("/accounts/keycloak/callback/?error=access_denied")
    assert response.status_code == 400


@responses.activate
@pytest.mark.django_db
def test_logout_ends_keycloak_sso_session_when_login_was_via_keycloak(signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(sub="keycloak-sub-1"))
    responses.post(TOKEN_ENDPOINT, json={"access_token": token, "id_token": "the-id-token"})

    client = Client()
    login_response = client.get("/accounts/keycloak/login/")
    state = parse_qs(urlparse(login_response.url).query)["state"][0]
    client.get(f"/accounts/keycloak/callback/?code=the-code&state={state}")
    assert client.session["pyobs_auth_id_token"] == "the-id-token"

    logout_response = client.post("/accounts/keycloak/logout/")

    assert logout_response.status_code == 302
    parsed = urlparse(logout_response.url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == END_SESSION_ENDPOINT
    assert parse_qs(parsed.query)["id_token_hint"] == ["the-id-token"]
    # local session is gone too
    assert "_auth_user_id" not in client.session


@pytest.mark.django_db
def test_logout_is_a_plain_local_logout_for_a_password_session():
    user = User.objects.create_user(username="localuser", password="pw")
    client = Client()
    client.force_login(user)
    assert "pyobs_auth_id_token" not in client.session

    response = client.post("/accounts/keycloak/logout/")

    assert response.status_code == 302
    assert response.url == "/"
    assert "_auth_user_id" not in client.session


def test_logout_only_accepts_post():
    client = Client()
    response = client.get("/accounts/keycloak/logout/")
    assert response.status_code == 405


@responses.activate
@pytest.mark.django_db
def test_login_view_uses_configured_idp_hint(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(PYOBS_AUTH={**settings.PYOBS_AUTH, "IDP_HINT": "gwdg"}):
        response = client.get("/accounts/keycloak/login/?next=/dashboard/")

    assert response.status_code == 302
    query = parse_qs(urlparse(response.url).query)
    assert query["kc_idp_hint"] == ["gwdg"]
    assert client.session["pyobs_auth_next"] == "/dashboard/"


@responses.activate
@pytest.mark.django_db
def test_login_view_empty_idp_hint_param_suppresses_the_hint(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(PYOBS_AUTH={**settings.PYOBS_AUTH, "IDP_HINT": "gwdg"}):
        response = client.get("/accounts/keycloak/login/?idp_hint=&next=/dashboard/")

    assert response.status_code == 302
    assert "kc_idp_hint" not in parse_qs(urlparse(response.url).query)
    assert client.session["pyobs_auth_next"] == "/dashboard/"


@responses.activate
@pytest.mark.django_db
def test_login_view_explicit_idp_hint_param_overrides_the_configured_default(signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    client = Client()

    with override_settings(PYOBS_AUTH={**settings.PYOBS_AUTH, "IDP_HINT": "gwdg"}):
        response = client.get("/accounts/keycloak/login/?idp_hint=other-idp&next=/dashboard/")

    assert response.status_code == 302
    assert parse_qs(urlparse(response.url).query)["kc_idp_hint"] == ["other-idp"]
