import time

import pytest
import responses

from pyobs_auth.validation import TokenValidationError, TokenValidator

from .helpers import register_discovery_and_jwks


@responses.activate
def test_validate_accepts_a_correctly_signed_token(keycloak_settings, signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims())

    claims = TokenValidator(keycloak_settings).validate(token)

    assert claims["sub"] == "abc-123"


@responses.activate
def test_validate_rejects_expired_token(keycloak_settings, signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    now = int(time.time())
    token = signing_keys.sign(make_claims(iat=now - 600, exp=now - 300))

    with pytest.raises(TokenValidationError):
        TokenValidator(keycloak_settings).validate(token)


@responses.activate
def test_validate_rejects_wrong_audience(keycloak_settings, signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(aud="some-other-client"))

    with pytest.raises(TokenValidationError):
        TokenValidator(keycloak_settings).validate(token)


@responses.activate
def test_validate_rejects_wrong_issuer(keycloak_settings, signing_keys, make_claims, monkeypatch):
    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    token = signing_keys.sign(make_claims(iss="https://not-our-keycloak.example.org/realms/other"))

    with pytest.raises(TokenValidationError):
        TokenValidator(keycloak_settings).validate(token)


@responses.activate
def test_validate_rejects_token_signed_by_a_different_key(keycloak_settings, signing_keys, make_claims, monkeypatch):
    from .helpers import generate_signing_keys

    register_discovery_and_jwks(responses, signing_keys, monkeypatch)
    other_keys = generate_signing_keys()  # same kid, different key -> signature won't match
    token = other_keys.sign(make_claims())

    with pytest.raises(TokenValidationError):
        TokenValidator(keycloak_settings).validate(token)


def test_unverified_issuer_does_not_require_network(keycloak_settings, signing_keys, make_claims):
    token = signing_keys.sign(make_claims(iss="https://someone-elses-keycloak.example.org/realms/x"))

    assert (
        TokenValidator(keycloak_settings).unverified_issuer(token) == "https://someone-elses-keycloak.example.org/realms/x"
    )


def test_unverified_issuer_returns_none_for_garbage(keycloak_settings):
    assert TokenValidator(keycloak_settings).unverified_issuer("not-a-jwt") is None
