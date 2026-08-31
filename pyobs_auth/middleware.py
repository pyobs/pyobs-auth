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
expiry - i.e. sessions never established via `CallbackView` (a local-password session), sessions
established before this middleware existed, and sessions where `CallbackView` declined to store
the refresh token at all (a cookie-backed `SESSION_ENGINE` - see `views.py`).

A failed refresh only ends the session when Keycloak's token endpoint says the grant is actually
invalid (`error: "invalid_grant"`) - a network error or a 5xx from Keycloak itself leaves the
session as-is and lets the next request retry, so a Keycloak outage doesn't mass-log-out every
active session. `invalid_grant` itself is ambiguous between "genuinely revoked" and "a harmless
race between two concurrent requests both refreshing the same soon-to-be-invalidated token" (only
relevant if the realm has refresh-token rotation/revocation enabled) - handled by re-reading the
session from its store before giving up.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from importlib import import_module

from django.conf import settings as django_settings
from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse

from .authorization import AuthorizationError, authorize
from .client import KeycloakClient, TokenExchangeError
from .settings import get_settings
from .validation import TokenValidationError, TokenValidator
from .views import SESSION_ACCESS_EXPIRES_KEY, SESSION_REFRESH_TOKEN_KEY

_logger = logging.getLogger(__name__)


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
        except TokenExchangeError as exc:
            self._handle_refresh_failure(request, exc)
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
        except ValueError:
            _logger.exception("PYOBS_AUTH['REQUIRED_ROLES'] is malformed")
            raise

        # Re-run the resolver so a claim-derived local flag (e.g. portal's `is_superuser` synced
        # from a client role) picks up a change made in Keycloak since login, not just at next
        # login - and so the *current* request sees it too, not only the next one.
        user_resolver = settings.resolve_user_callable()
        refreshed_user = user_resolver(claims)
        if refreshed_user is None:
            logout(request)
            return
        request.user = refreshed_user

        request.session[SESSION_ACCESS_EXPIRES_KEY] = claims["exp"]
        new_refresh_token = tokens.get("refresh_token")
        if new_refresh_token:
            request.session[SESSION_REFRESH_TOKEN_KEY] = new_refresh_token

    def _handle_refresh_failure(self, request: HttpRequest, exc: TokenExchangeError) -> None:
        if exc.error_code != "invalid_grant":
            # Keycloak unreachable, a 5xx, a malformed response, etc. - not evidence of
            # revocation. Leave the session as-is; the next request retries. No backoff/
            # rate-limiting here - retrying every request during an outage is an accepted
            # tradeoff at this fleet's scale. debug, not warning: during an outage this fires
            # once per expired session per request, which would otherwise flood logs.
            _logger.debug("Keycloak refresh_token grant failed (not invalid_grant): %s", exc)
            return

        # invalid_grant can mean a genuinely revoked/expired grant, or a benign race: two
        # concurrent requests both saw the access token as expired and both tried to refresh the
        # same refresh token - if the realm rotates/revokes refresh tokens on use, only the first
        # succeeds and the second gets invalid_grant even though nothing was actually revoked.
        # Re-read the session fresh from its store (not the in-memory request.session, which may
        # be stale relative to what the concurrent request already wrote) before giving up.
        fresh = self._fresh_session(request)
        fresh_expires_at = fresh.get(SESSION_ACCESS_EXPIRES_KEY) if fresh is not None else None
        if fresh_expires_at is not None and fresh_expires_at > time.time():
            request.session[SESSION_ACCESS_EXPIRES_KEY] = fresh_expires_at
            fresh_refresh_token = fresh.get(SESSION_REFRESH_TOKEN_KEY)
            if fresh_refresh_token is not None:
                request.session[SESSION_REFRESH_TOKEN_KEY] = fresh_refresh_token
            return

        logout(request)

    @staticmethod
    def _fresh_session(request: HttpRequest):
        session_key = request.session.session_key
        if not session_key:
            return None
        engine = import_module(django_settings.SESSION_ENGINE)
        return engine.SessionStore(session_key=session_key)
