"""Session-refresh middleware: once the access token that established a browser session has
expired, silently exchange the stored refresh token for a new one, re-validate the resulting
claims, and re-run the authorization gate - ending the session if it now fails.

Without this, a plain Django session never re-contacts Keycloak after login, so a revoked group/
role (or a synced local flag like `is_superuser`) would only take effect at the user's next login,
bounded only by `SESSION_COOKIE_AGE`, not by any token lifetime. See pyobs-core's
`specs/design/shared-authz-keycloak.md`, "Revocation model and freshness".

Runs lazily, on whichever request happens to land after expiry - no background task, and no
Keycloak round trip at all while the cached access token is still valid, so this doesn't add a
per-request network dependency.

Add to `MIDDLEWARE`, after `AuthenticationMiddleware` (needs `request.user`)::

    MIDDLEWARE = [
        ...,
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "pyobs_auth.middleware.KeycloakSessionRefreshMiddleware",
    ]

A no-op for any request whose session doesn't carry both a refresh token and an access-token
expiry - i.e. sessions never established via `CallbackView` (a local-password session) and
sessions established before this middleware existed.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse

from .authorization import AuthorizationError, authorize
from .client import KeycloakClient, TokenExchangeError
from .settings import get_settings
from .validation import TokenValidationError, TokenValidator
from .views import SESSION_ACCESS_EXPIRES_KEY, SESSION_REFRESH_TOKEN_KEY


class KeycloakSessionRefreshMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self._maybe_refresh(request)
        return self.get_response(request)

    def _maybe_refresh(self, request: HttpRequest) -> None:
        expires_at = request.session.get(SESSION_ACCESS_EXPIRES_KEY)
        refresh_token = request.session.get(SESSION_REFRESH_TOKEN_KEY)
        if expires_at is None or refresh_token is None:
            return
        if time.time() < expires_at:
            return

        settings = get_settings()
        client = KeycloakClient(settings)
        try:
            tokens = client.refresh(refresh_token=refresh_token)
        except TokenExchangeError:
            logout(request)
            return

        access_token = tokens.get("access_token")
        if not access_token:
            logout(request)
            return

        validator = TokenValidator(settings)
        try:
            claims = validator.validate(access_token)
        except TokenValidationError:
            logout(request)
            return

        if settings.enforce_local_active and not request.user.is_active:
            logout(request)
            return
        try:
            authorize(claims, settings)
        except AuthorizationError:
            logout(request)
            return

        # Re-run the resolver so a claim-derived local flag (e.g. portal's `is_superuser` synced
        # from a client role) picks up a change made in Keycloak since login, not just at next
        # login.
        user_resolver = settings.resolve_user_callable()
        user_resolver(claims)

        request.session[SESSION_ACCESS_EXPIRES_KEY] = claims["exp"]
        new_refresh_token = tokens.get("refresh_token")
        if new_refresh_token:
            request.session[SESSION_REFRESH_TOKEN_KEY] = new_refresh_token
