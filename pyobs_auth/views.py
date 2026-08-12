"""Browser-facing login flow: authorization-code + PKCE redirect to Keycloak and back.

Not a django.contrib.auth AUTHENTICATION_BACKENDS class - that shape fits a synchronous
credential check (username+password in, User out), not a redirect-based OIDC flow. These are
plain Django views instead; wire them in via pyobs_auth.urls.
"""

from __future__ import annotations

from django.conf import settings as django_settings
from django.contrib.auth import login, logout
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest, HttpResponseRedirect
from django.views import View

from .client import KeycloakClient, TokenExchangeError
from .settings import get_settings
from .validation import TokenValidationError, TokenValidator

SESSION_STATE_KEY = "pyobs_auth_state"
SESSION_CODE_VERIFIER_KEY = "pyobs_auth_code_verifier"
SESSION_NEXT_KEY = "pyobs_auth_next"
# Presence of this key is also how LogoutView tells "this session came from Keycloak" apart from
# a plain local-password session, so it knows whether to also end the Keycloak SSO session.
SESSION_ID_TOKEN_KEY = "pyobs_auth_id_token"


class LoginView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        settings = get_settings()
        client = KeycloakClient(settings)
        authorization = client.start_authorization()

        request.session[SESSION_STATE_KEY] = authorization.state
        request.session[SESSION_CODE_VERIFIER_KEY] = authorization.code_verifier
        # `or "/"` (not just a dict default) because `?next=` with an empty value is a present-but-
        # falsy key - `.get("next", "/")` alone would return "" instead of falling back to "/".
        request.session[SESSION_NEXT_KEY] = request.GET.get("next") or "/"

        return HttpResponseRedirect(authorization.url)


class CallbackView(View):
    def get(self, request: HttpRequest) -> HttpResponse:
        error = request.GET.get("error")
        if error:
            return HttpResponseBadRequest(f"Keycloak login failed: {error}")

        code = request.GET.get("code")
        state = request.GET.get("state")
        expected_state = request.session.pop(SESSION_STATE_KEY, None)
        code_verifier = request.session.pop(SESSION_CODE_VERIFIER_KEY, None)
        next_url = request.session.pop(SESSION_NEXT_KEY, "/") or "/"

        if not code or not state or not code_verifier or state != expected_state:
            return HttpResponseBadRequest("Invalid or expired login state")

        settings = get_settings()
        client = KeycloakClient(settings)

        try:
            tokens = client.exchange_code(code=code, code_verifier=code_verifier)
        except TokenExchangeError as exc:
            return HttpResponseBadRequest(f"Token exchange failed: {exc}")

        access_token = tokens.get("access_token")
        if not access_token:
            return HttpResponseBadRequest("No access_token in Keycloak's response")

        validator = TokenValidator(settings)
        try:
            claims = validator.validate(access_token)
        except TokenValidationError as exc:
            return HttpResponseBadRequest(f"Received an invalid token: {exc}")

        user_resolver = settings.resolve_user_callable()
        user = user_resolver(claims)
        if user is None:
            return HttpResponseBadRequest("No local user for this token")
        if not user.is_active:
            return HttpResponseBadRequest("Account pending activation")

        backend = getattr(django_settings, "PYOBS_AUTH_LOGIN_BACKEND", "django.contrib.auth.backends.ModelBackend")
        login(request, user, backend=backend)
        # Set after login(), which rotates the session key - setting it before would risk the
        # value getting lost if that rotation ever stopped preserving existing session data.
        id_token = tokens.get("id_token")
        if id_token:
            request.session[SESSION_ID_TOKEN_KEY] = id_token

        return HttpResponseRedirect(next_url)


class LogoutView(View):
    """Ends the local Django session and, only if this session was established via Keycloak
    (an id_token was stored at login), also ends the Keycloak SSO session via RP-Initiated
    Logout - so a plain local-password session just gets an ordinary local logout, unaffected."""

    http_method_names = ["post"]

    def post(self, request: HttpRequest) -> HttpResponse:
        id_token = request.session.pop(SESSION_ID_TOKEN_KEY, None)
        logout(request)

        if id_token is None:
            next_url = request.POST.get("next") or request.GET.get("next") or "/"
            return HttpResponseRedirect(next_url)

        # post_logout_redirect_uri here deliberately comes only from PYOBS_AUTH (a fixed,
        # pre-registered absolute URL, like REDIRECT_URI for login) rather than from a per-request
        # `next` - Keycloak validates it against "Valid post logout redirect URIs" for the client,
        # so an arbitrary relative path wouldn't match and the redirect would fail.
        settings = get_settings()
        client = KeycloakClient(settings)
        return HttpResponseRedirect(client.end_session_url(id_token_hint=id_token))
