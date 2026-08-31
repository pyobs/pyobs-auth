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
        "REQUIRED_GROUPS": ["/pyobs-archive"],
        "REQUIRED_ROLES": ["client:archive:archive-admin"],
        "ENFORCE_LOCAL_ACTIVE": False,
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

``REQUIRED_GROUPS`` (default: unset — no group gate)
    Full Keycloak group paths (e.g. ``["/pyobs-archive"]``), matched against the validated
    token's ``groups`` claim. Any *one* listed group is enough. This is the "may this person use
    this service at all" gate — see :ref:`authorization` below.

``REQUIRED_ROLES`` (default: unset — no role gate)
    Realm or client roles, matched against ``realm_access.roles`` /
    ``resource_access.<client>.roles``. Entries are ``"realm:<role>"`` or
    ``"client:<client_id>:<role>"`` (e.g. ``"client:portal:portal-admin"``). Any *one* listed role
    is enough. If both ``REQUIRED_GROUPS`` and ``REQUIRED_ROLES`` are set, **both** must be
    satisfied — ``REQUIRED_ROLES`` is a stricter sub-gate layered on top of the group check, not
    an alternative path around it.

``ENFORCE_LOCAL_ACTIVE`` (default: ``False``)
    When ``True``, a resolved user with ``is_active=False`` is refused, on top of whatever
    ``REQUIRED_GROUPS``/``REQUIRED_ROLES`` decide. See :ref:`authorization` below — this is an
    opt-in local kill switch, not the default authorization decision.

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

Authorization
*************

By default (no ``REQUIRED_GROUPS``/``REQUIRED_ROLES``/``ENFORCE_LOCAL_ACTIVE`` set), pyobs-auth
only authenticates — anyone who can produce a validly-signed, unexpired token for this realm is
let in, and the local ``is_active`` flag is never consulted. Setting ``REQUIRED_GROUPS`` and/or
``REQUIRED_ROLES`` turns on the claims-based *authorization* gate, checked before a local
``User`` is even resolved: an unauthorized token never reaches ``USER_RESOLVER``, so no local
account gets minted for someone who isn't allowed in at all.

**Reproducing the old default (manual per-service activation)**: set
``ENFORCE_LOCAL_ACTIVE=True`` and leave ``REQUIRED_GROUPS``/``REQUIRED_ROLES`` unset, and have
``USER_RESOLVER`` keep minting new accounts with ``is_active=False`` — first login mints an
inactive user, an admin activates it in Django admin, and only then does login work. This is
exactly pyobs-auth's pre-authorization behavior.

**Failure mode to avoid**: upgrading pyobs-auth without also reviewing these settings silently
drops any activation gate you were relying on — ``ENFORCE_LOCAL_ACTIVE`` defaults to ``False``
and unset ``REQUIRED_*`` settings mean no claims gate either, so *every* authenticating Keycloak
user becomes authorized. If your deployment relies on the old manual-activation behavior, set
``ENFORCE_LOCAL_ACTIVE=True`` explicitly as part of the upgrade. The reverse mistake — setting
``REQUIRED_GROUPS`` before anyone has actually been assigned to that group in Keycloak — locks
everyone out, including yourself.

**Revocation freshness**: token validation is stateless, so a browser session's claims are only
as fresh as the token that established it. ``KeycloakSessionRefreshMiddleware`` (see
:doc:`installation`) is what keeps a long-lived session honest: once the access token has
expired, it silently refreshes via the stored refresh token, re-validates, and re-runs the
authorization gate — ending the session if a group/role was revoked in Keycloak in the meantime.
Without this middleware installed, a revoked user stays logged in until their session cookie
itself expires (``SESSION_COOKIE_AGE``), which is typically much longer than one access-token
lifetime.
