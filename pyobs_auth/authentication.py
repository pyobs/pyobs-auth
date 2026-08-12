"""DRF authentication backed by pyobs-auth's JWKS token validation.

Single issuer only (the one Keycloak realm in PYOBS_AUTH) - there is deliberately no multi-issuer
support here. See pyobs-core's shared-auth design doc for why: any upstream identity provider
(including a self-hosted observation-portal) is meant to be brokered *behind* Keycloak, not
validated directly by this class, so archive/robotic-backend/etc. only ever need to trust one
issuer.
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

        try:
            claims = validator.validate(token)
        except TokenValidationError as exc:
            raise exceptions.AuthenticationFailed(str(exc)) from exc

        user_resolver = settings.resolve_user_callable()
        user = user_resolver(claims)
        if user is None:
            raise exceptions.AuthenticationFailed("No local user for this token")

        return (user, claims)

    def authenticate_header(self, request):
        return f'Bearer realm="{self.www_authenticate_realm}"'
