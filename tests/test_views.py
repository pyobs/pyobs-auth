from urllib.parse import parse_qs, urlparse

import pytest
import responses
from django.contrib.auth.models import User
from django.test import Client

from .helpers import TOKEN_ENDPOINT, register_discovery_and_jwks


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
