from urllib.parse import parse_qs, urlparse

import pytest
import responses

from pyobs_auth.client import KeycloakClient, TokenExchangeError

from .helpers import AUTHORIZATION_ENDPOINT, TOKEN_ENDPOINT, register_discovery_and_jwks


@responses.activate
def test_start_authorization_builds_a_pkce_url(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)

    result = KeycloakClient(keycloak_settings).start_authorization()

    parsed = urlparse(result.url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == AUTHORIZATION_ENDPOINT
    query = parse_qs(parsed.query)
    assert query["client_id"] == ["archive"]
    assert query["redirect_uri"] == ["https://archive.example.org/accounts/keycloak/callback/"]
    assert query["response_type"] == ["code"]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [result.state]
    # code_verifier itself must never appear in the URL
    assert result.code_verifier not in result.url


@responses.activate
def test_start_authorization_requires_a_redirect_uri(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    from dataclasses import replace

    settings_without_redirect = replace(keycloak_settings, redirect_uri=None)

    with pytest.raises(ValueError):
        KeycloakClient(settings_without_redirect).start_authorization()


@responses.activate
def test_exchange_code_posts_expected_params(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, json={"access_token": "at", "refresh_token": "rt", "id_token": "it"})

    tokens = KeycloakClient(keycloak_settings).exchange_code(code="the-code", code_verifier="the-verifier")

    assert tokens == {"access_token": "at", "refresh_token": "rt", "id_token": "it"}
    sent = parse_qs(responses.calls[-1].request.body)
    assert sent["grant_type"] == ["authorization_code"]
    assert sent["code"] == ["the-code"]
    assert sent["code_verifier"] == ["the-verifier"]
    assert sent["client_secret"] == ["test-secret"]


@responses.activate
def test_exchange_code_raises_on_error_response(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant"})

    with pytest.raises(TokenExchangeError):
        KeycloakClient(keycloak_settings).exchange_code(code="bad-code", code_verifier="v")


@responses.activate
def test_client_credentials_token(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, json={"access_token": "service-token"})

    tokens = KeycloakClient(keycloak_settings).client_credentials_token()

    assert tokens["access_token"] == "service-token"
    sent = parse_qs(responses.calls[-1].request.body)
    assert sent["grant_type"] == ["client_credentials"]


def test_client_credentials_token_requires_secret(keycloak_settings):
    from dataclasses import replace

    public_settings = replace(keycloak_settings, client_secret=None)
    with pytest.raises(ValueError):
        KeycloakClient(public_settings).client_credentials_token()


@responses.activate
def test_refresh(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, json={"access_token": "new-at"})

    tokens = KeycloakClient(keycloak_settings).refresh(refresh_token="old-rt")

    assert tokens["access_token"] == "new-at"
    sent = parse_qs(responses.calls[-1].request.body)
    assert sent["grant_type"] == ["refresh_token"]
    assert sent["refresh_token"] == ["old-rt"]
