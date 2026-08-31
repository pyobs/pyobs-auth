"""Session refresh + re-authorization, so a browser session doesn't just trust its access token
claims forever between logins.

Without this, a plain Django session has no further contact with Keycloak until logout or
SESSION_COOKIE_AGE - a revoked group/role would only take effect at next login, which for a
long-lived session cookie could be days. This middleware bounds that instead to roughly one
access-token lifetime: once the access token (whose `exp` was stashed at login/last refresh) has
expired, it silently refreshes via the stored refresh_token, re-validates the new claims, and
re-runs authorize() - ending the session if it now fails. See pyobs-core's shared-authz design
doc, "Revocation model and freshness".

Only acts on sessions that went through CallbackView (i.e. carry SESSION_REFRESH_TOKEN_KEY and
SESSION_ACCESS_TOKEN_EXP_KEY) - a locally-authenticated (createsuperuser / Django-admin) session,
or one from before this middleware existed, has neither and is left untouched.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse

from .authorization import authorize
from .client import KeycloakClient, TokenExchangeError
from .settings import get_settings
from .validation import TokenValidationError, TokenValidator
from .views import SESSION_ACCESS_TOKEN_EXP_KEY, SESSION_ID_TOKEN_KEY, SESSION_REFRESH_TOKEN_KEY


class KeycloakSessionRefreshMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        self._maybe_refresh(request)
        return self.get_response(request)

    def _maybe_refresh(self, request: HttpRequest) -> None:
        refresh_token = request.session.get(SESSION_REFRESH_TOKEN_KEY)
        exp = request.session.get(SESSION_ACCESS_TOKEN_EXP_KEY)
        if refresh_token is None or exp is None:
            return
        if time.time() < exp:
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

        if not authorize(claims, settings):
            logout(request)
            return

        # Re-run the resolver so any locally-synced claim-derived flags (e.g. a service's
        # is_superuser sync from a client role) re-derive on this same refresh cycle, not just at
        # login - the design doc's revocation-freshness guarantee depends on this happening
        # somewhere, and this middleware is the only place positioned to do it outside the login
        # path.
        user_resolver = settings.resolve_user_callable()
        user_resolver(claims)

        request.session[SESSION_ACCESS_TOKEN_EXP_KEY] = claims["exp"]
        new_refresh_token = tokens.get("refresh_token")
        if new_refresh_token:
            request.session[SESSION_REFRESH_TOKEN_KEY] = new_refresh_token
        new_id_token = tokens.get("id_token")
        if new_id_token:
            request.session[SESSION_ID_TOKEN_KEY] = new_id_token
