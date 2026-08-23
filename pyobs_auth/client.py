"""OIDC client: authorization-code + PKCE for user login, client-credentials for
service-to-service - both against a single Keycloak realm (see settings.py)."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import requests

from .discovery import fetch_discovery_document
from .settings import KeycloakSettings


class TokenExchangeError(Exception):
    pass


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class AuthorizationRequest:
    """Result of starting a login: send the user to `url`, keep `code_verifier` server-side
    (e.g. in the session) until the callback arrives."""

    url: str
    state: str
    code_verifier: str


class KeycloakClient:
    def __init__(self, settings: KeycloakSettings, *, session: requests.Session | None = None) -> None:
        self._settings = settings
        self._session = session or requests.Session()

    def _discovery(self):
        return fetch_discovery_document(self._settings.discovery_url)

    def start_authorization(
        self, *, idp_hint: str | None = None, redirect_uri: str | None = None
    ) -> AuthorizationRequest:
        """Build the redirect URL for the authorization-code + PKCE login flow."""
        document = self._discovery()
        state = _b64url(secrets.token_bytes(24))
        code_verifier = _b64url(secrets.token_bytes(48))
        code_challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())

        effective_redirect_uri = redirect_uri or self._settings.redirect_uri
        if not effective_redirect_uri:
            raise ValueError("redirect_uri must be set (either PYOBS_AUTH['REDIRECT_URI'] or the redirect_uri arg)")

        params = {
            "response_type": "code",
            "client_id": self._settings.client_id,
            "redirect_uri": effective_redirect_uri,
            "scope": " ".join(self._settings.scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if idp_hint:
            # kc_idp_hint: Keycloak skips its login/IdP-selection page and redirects straight to
            # that identity provider; unknown aliases fall back to the normal login page.
            params["kc_idp_hint"] = idp_hint
        url = f"{document.authorization_endpoint}?{urlencode(params)}"
        return AuthorizationRequest(url=url, state=state, code_verifier=code_verifier)

    def exchange_code(self, *, code: str, code_verifier: str, redirect_uri: str | None = None) -> dict[str, Any]:
        """Swap an authorization code for tokens (access_token, refresh_token, id_token, ...)."""
        document = self._discovery()
        effective_redirect_uri = redirect_uri or self._settings.redirect_uri
        if not effective_redirect_uri:
            raise ValueError("redirect_uri must be set (either PYOBS_AUTH['REDIRECT_URI'] or the redirect_uri arg)")

        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": effective_redirect_uri,
            "client_id": self._settings.client_id,
            "code_verifier": code_verifier,
        }
        if self._settings.client_secret:
            data["client_secret"] = self._settings.client_secret

        return self._post_token(document.token_endpoint, data)

    def client_credentials_token(self, *, scope: str | None = None) -> dict[str, Any]:
        """Service-to-service token, e.g. for one pyobs web service to call another's API."""
        if not self._settings.client_secret:
            raise ValueError("client_credentials grant requires PYOBS_AUTH['CLIENT_SECRET']")

        document = self._discovery()
        data = {
            "grant_type": "client_credentials",
            "client_id": self._settings.client_id,
            "client_secret": self._settings.client_secret,
        }
        if scope:
            data["scope"] = scope

        return self._post_token(document.token_endpoint, data)

    def refresh(self, *, refresh_token: str) -> dict[str, Any]:
        document = self._discovery()
        data = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._settings.client_id,
        }
        if self._settings.client_secret:
            data["client_secret"] = self._settings.client_secret

        return self._post_token(document.token_endpoint, data)

    def end_session_url(self, *, id_token_hint: str, post_logout_redirect_uri: str | None = None) -> str:
        """RP-Initiated Logout: URL to send the browser to end the user's Keycloak SSO session.

        `id_token_hint` lets Keycloak log the user out with a single redirect instead of showing
        a confirmation page - so an id_token needs to have been kept around from login for this
        to give a clean one-click logout.
        """
        document = self._discovery()
        if not document.end_session_endpoint:
            raise ValueError("this Keycloak realm did not advertise an end_session_endpoint")

        effective_redirect_uri = post_logout_redirect_uri or self._settings.post_logout_redirect_uri
        params = {"id_token_hint": id_token_hint, "client_id": self._settings.client_id}
        if effective_redirect_uri:
            params["post_logout_redirect_uri"] = effective_redirect_uri

        return f"{document.end_session_endpoint}?{urlencode(params)}"

    def _post_token(self, token_endpoint: str, data: dict[str, str]) -> dict[str, Any]:
        response = self._session.post(token_endpoint, data=data, timeout=10.0)
        if response.status_code != 200:
            raise TokenExchangeError(f"token endpoint returned {response.status_code}: {response.text}")
        return response.json()
