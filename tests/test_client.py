from urllib.parse import parse_qs, urlparse

import pytest
import responses

from pyobs_auth.client import KeycloakClient, TokenExchangeError

from .helpers import AUTHORIZATION_ENDPOINT, END_SESSION_ENDPOINT, TOKEN_ENDPOINT, register_discovery_and_jwks


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
def test_post_token_error_exposes_oauth_error_code(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, status=400, json={"error": "invalid_grant", "error_description": "expired"})

    with pytest.raises(TokenExchangeError) as excinfo:
        KeycloakClient(keycloak_settings).refresh(refresh_token="old-rt")

    assert excinfo.value.error_code == "invalid_grant"


@responses.activate
def test_post_token_error_with_non_json_body_has_no_error_code(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, status=502, body="Bad Gateway")

    with pytest.raises(TokenExchangeError) as excinfo:
        KeycloakClient(keycloak_settings).refresh(refresh_token="old-rt")

    assert excinfo.value.error_code is None


@responses.activate
def test_post_token_wraps_connection_error(keycloak_settings, signing_keys, monkeypatch):
    import requests

    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    responses.post(TOKEN_ENDPOINT, body=requests.exceptions.ConnectionError("boom"))

    with pytest.raises(TokenExchangeError) as excinfo:
        KeycloakClient(keycloak_settings).refresh(refresh_token="old-rt")

    assert excinfo.value.error_code is None
    assert "could not reach token endpoint" in str(excinfo.value)


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


@responses.activate
def test_end_session_url_uses_configured_post_logout_redirect(keycloak_settings, signing_keys, monkeypatch):
    from dataclasses import replace

    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    settings = replace(keycloak_settings, post_logout_redirect_uri="https://archive.example.org/")

    url = KeycloakClient(settings).end_session_url(id_token_hint="the-id-token")

    parsed = urlparse(url)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == END_SESSION_ENDPOINT
    query = parse_qs(parsed.query)
    assert query["id_token_hint"] == ["the-id-token"]
    assert query["client_id"] == ["archive"]
    assert query["post_logout_redirect_uri"] == ["https://archive.example.org/"]


@responses.activate
def test_end_session_url_omits_post_logout_redirect_when_unconfigured(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)

    url = KeycloakClient(keycloak_settings).end_session_url(id_token_hint="the-id-token")

    assert "post_logout_redirect_uri" not in parse_qs(urlparse(url).query)


@responses.activate
def test_start_authorization_with_idp_hint(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)

    result = KeycloakClient(keycloak_settings).start_authorization(idp_hint="gwdg")

    assert parse_qs(urlparse(result.url).query)["kc_idp_hint"] == ["gwdg"]


@responses.activate
def test_start_authorization_omits_idp_hint_when_absent(keycloak_settings, signing_keys, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)

    result = KeycloakClient(keycloak_settings).start_authorization()

    assert "kc_idp_hint" not in parse_qs(urlparse(result.url).query)
