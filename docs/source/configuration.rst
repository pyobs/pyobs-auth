Configuration
#############

Everything is configured through the ``PYOBS_AUTH`` Django setting, plus ``DEFAULT_AUTHENTICATION_CLASSES``
for DRF::

    PYOBS_AUTH = {
        "SERVER_URL": "https://keycloak.example.org",
        "REALM": "pyobs",
        "CLIENT_ID": "archive",
        "CLIENT_SECRET": os.getenv("KEYCLOAK_CLIENT_SECRET"),
        "REDIRECT_URI": "https://archive.example.org/accounts/keycloak/callback/",
        "POST_LOGOUT_REDIRECT_URI": "https://archive.example.org/",
        "USER_RESOLVER": "myapp.authentication.resolve_user",
        "IDP_HINT": "gwdg",
    }

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "pyobs_auth.authentication.KeycloakAuthentication",
            # ... any other authentication classes that must keep working, e.g. an existing
            # DRF TokenAuthentication for service-to-service calls - additive, not a replacement.
        ],
    }

``SERVER_URL``, ``REALM``, ``CLIENT_ID`` (required)
    The single Keycloak realm and this service's client within it. See :doc:`architecture` for
    why only one realm is supported at all.

``CLIENT_SECRET`` (default: unset)
    Required for the client-credentials grant (``KeycloakClient.get_service_token()``) and to
    exchange an authorization code server-side; not needed for token validation alone.

``AUDIENCE`` (default: ``CLIENT_ID``)
    Expected ``aud`` claim on validated tokens, if it differs from ``CLIENT_ID``.

``REDIRECT_URI`` (default: unset)
    Must match a "Valid Redirect URI" registered for this client in Keycloak. Required to use the
    browser login flow (:doc:`installation`).

``POST_LOGOUT_REDIRECT_URI`` (default: unset)
    Must match a "Valid post logout redirect URI" registered for this client in Keycloak.
    Optional — only needed to use ``LogoutView``'s Keycloak SSO logout (RP-Initiated Logout); a
    Keycloak session still gets an ordinary local logout without it.

``SCOPES`` (default: ``["openid", "profile", "email"]``)
    OIDC scopes requested during login.

``USER_RESOLVER`` (default: unset — required to actually log a user in)
    Dotted path to a ``callable(claims: dict) -> django.contrib.auth.models.User | None``. See
    below.

``IDP_HINT`` (default: unset)
    Passed to Keycloak's authorization endpoint as ``kc_idp_hint``, skipping its login/IdP-selection
    page and going straight to that identity provider (e.g. an institute SSO). The alias is
    deployment-specific to your realm. The login view also accepts an ``?idp_hint=`` query param
    that overrides this per request: present-but-empty disables the hint for that login (a
    "log in with local Keycloak account" button); ``?idp_hint=<alias>`` uses that alias.

``USER_RESOLVER``
******************

pyobs-auth deliberately doesn't decide how a validated token maps to your app's local ``User``
model — each service's schema is different (e.g. pyobs-archive's existing ``Profile`` model vs.
pyobs-portal, which has none). Provide a callable that takes the validated JWT claims and returns
a ``User`` (or ``None`` to reject)::

    from django.contrib.auth.models import User


    def resolve_user(claims: dict) -> User | None:
        # Keycloak's `sub` claim is the join key - stable across username/email changes,
        # and the same whether the user authenticated locally or via a brokered upstream IdP.
        user, _ = User.objects.get_or_create(
            keycloak_sub=claims["sub"],
            defaults={"username": claims.get("preferred_username", claims["sub"])},
        )
        return user
