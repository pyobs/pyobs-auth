"""DRF authentication backed by pyobs-auth's JWKS token validation.

Single issuer only (the one Keycloak realm in PYOBS_AUTH) - there is deliberately no multi-issuer
support here. See pyobs-core's shared-auth design doc for why: any upstream identity provider
(including a self-hosted observation-portal) is meant to be brokered *behind* Keycloak, not
validated directly by this class, so archive/portal/etc. only ever need to trust one
issuer.

This class is written to be safe to stack alongside another Bearer-scheme authenticator that
can't be modified (e.g. an existing legacy OAuth2 BearerAuthentication) - see below.

Authorization (may this token's user use this service at all) is decided by claims alone, before
any local User is resolved - see authorization.py. The local `is_active` flag is a separate,
opt-in kill switch (PYOBS_AUTH["ENFORCE_LOCAL_ACTIVE"], default False) for deployments that want a
Keycloak-independent local override on top of the claims gate; it is not the default path.
"""

from __future__ import annotations

from rest_framework import authentication, exceptions

from .authorization import authorize
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

        # Claims-only check, before resolving/minting a local User - someone who isn't authorized
        # at all shouldn't cause a local account to be created.
        if not authorize(claims, settings):
            raise exceptions.AuthenticationFailed("not authorized")

        user_resolver = settings.resolve_user_callable()
        user = user_resolver(claims)
        if user is None:
            raise exceptions.AuthenticationFailed("No local user for this token")
        if settings.enforce_local_active and not user.is_active:
            raise exceptions.AuthenticationFailed("Account pending activation")

        return (user, claims)

    def authenticate_header(self, request):
        return f'Bearer realm="{self.www_authenticate_realm}"'
