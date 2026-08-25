"""DRF authentication backed by pyobs-auth's JWKS token validation.

Single issuer only (the one Keycloak realm in PYOBS_AUTH) - there is deliberately no multi-issuer
support here. See pyobs-core's shared-auth design doc for why: any upstream identity provider
(including a self-hosted observation-portal) is meant to be brokered *behind* Keycloak, not
validated directly by this class, so archive/portal/etc. only ever need to trust one
issuer.

This class is written to be safe to stack alongside another Bearer-scheme authenticator that
can't be modified (e.g. an existing legacy OAuth2 BearerAuthentication) - see below.

A resolved user with `is_active=False` is refused - USER_RESOLVER implementations mint new
accounts inactive by convention, giving each service an independent local activation gate on top
of whatever access control Keycloak itself does (a kill switch that doesn't depend on Keycloak
realm/client config alone).
"""

from __future__ import annotations

from rest_framework import authentication, exceptions

from .settings import get_settings
from .validation import TokenValidationError, TokenValidator


class KeycloakAuthentication(authentication.BaseAuthentication):
    www_authenticate_realm = "api"

    def authenticate(self, request):
        auth_header = authentication.get_authorization_header(request).split()
        if not auth_header or auth_header[0].lower() != b"bearer":
            return None
        if len(auth_header) != 2:
            raise exceptions.AuthenticationFailed("Invalid Authorization header")

        token = auth_header[1].decode()
        settings = get_settings()
        validator = TokenValidator(settings)

        # DRF stops the whole authenticator chain on a raise, unlike a `None` return, which just
        # falls through to the next class. If another Bearer-scheme authenticator is also
        # registered (e.g. a legacy OAuth2 BearerAuthentication that can't be modified to do the
        # same check), a token that was never meant for us must not block it from getting a turn -
        # so defer (return None) for anything that doesn't even claim to be from our issuer, and
        # only raise once we know the token was meant for us but is actually invalid.
        if validator.unverified_issuer(token) != settings.issuer:
            return None

        try:
            claims = validator.validate(token)
        except TokenValidationError as exc:
            raise exceptions.AuthenticationFailed(str(exc)) from exc

        user_resolver = settings.resolve_user_callable()
        user = user_resolver(claims)
        if user is None:
            raise exceptions.AuthenticationFailed("No local user for this token")
        if not user.is_active:
            raise exceptions.AuthenticationFailed("Account pending activation")

        return (user, claims)

    def authenticate_header(self, request):
        return f'Bearer realm="{self.www_authenticate_realm}"'
