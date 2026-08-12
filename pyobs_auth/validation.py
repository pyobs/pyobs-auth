"""Local, stateless bearer-token validation against a Keycloak realm's JWKS.

No per-request network round-trip to Keycloak (unlike introspection-style validation) - the
realm's signing keys are fetched once and cached (PyJWKClient does its own key-id-keyed caching,
refetching only on a cache miss, e.g. after key rotation).
"""

from __future__ import annotations

from typing import Any

import jwt
from jwt import PyJWKClient

from .discovery import fetch_discovery_document
from .settings import KeycloakSettings

_jwk_clients: dict[str, PyJWKClient] = {}


class TokenValidationError(Exception):
    pass


def clear_jwk_client_cache() -> None:
    """Only needed for tests - the cache is otherwise process-lifetime."""
    _jwk_clients.clear()


def _jwk_client_for(jwks_uri: str) -> PyJWKClient:
    client = _jwk_clients.get(jwks_uri)
    if client is None:
        client = PyJWKClient(jwks_uri)
        _jwk_clients[jwks_uri] = client
    return client


class TokenValidator:
    """Validates bearer tokens issued by one Keycloak realm (see KeycloakSettings)."""

    def __init__(self, settings: KeycloakSettings) -> None:
        self._settings = settings

    def unverified_issuer(self, token: str) -> str | None:
        """Peek at the (unverified) `iss` claim without validating the token.

        Lets a caller cheaply tell "not mine" from "mine but invalid" before deciding whether to
        raise - relevant if multiple authenticators are ever stacked against the same Bearer
        header (see pyobs-core's shared-auth design doc for why that matters).
        """
        try:
            claims = jwt.decode(token, options={"verify_signature": False, "verify_aud": False, "verify_exp": False})
        except jwt.InvalidTokenError:
            return None
        return claims.get("iss")

    def validate(self, token: str) -> dict[str, Any]:
        document = fetch_discovery_document(self._settings.discovery_url)
        jwk_client = _jwk_client_for(document.jwks_uri)

        try:
            signing_key = jwk_client.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientError as exc:
            raise TokenValidationError(f"could not resolve signing key: {exc}") from exc

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=document.issuer,
                audience=self._settings.expected_audience,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.InvalidTokenError as exc:
            raise TokenValidationError(str(exc)) from exc

        return claims
