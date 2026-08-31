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
        "REQUIRED_GROUPS": ["/myapp"],
        "REQUIRED_ROLES": ["client:myapp:myapp-admin"],
        "ENFORCE_LOCAL_ACTIVE": False,
    }

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            "pyobs_auth.authentication.KeycloakAuthentication",
            # ... any other authentication classes that must keep working, e.g. an existing
            # DRF TokenAuthentication for service-to-service calls - additive, not a replacement.
        ],
    }

    MIDDLEWARE = [
        ...,
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        # after AuthenticationMiddleware - needs request.user. See "Session refresh" below.
        "pyobs_auth.middleware.KeycloakSessionRefreshMiddleware",
    ]

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

``REQUIRED_GROUPS`` (default: unset — no gate)
    Full Keycloak group paths (e.g. ``["/myapp"]``) that must all be present in the token's
    ``groups`` claim. See :ref:`authorization` below.

``REQUIRED_ROLES`` (default: unset — no gate)
    Realm/client roles that must all be present, as ``"realm:<role>"`` (checked against
    ``realm_access.roles``) or ``"client:<client_id>:<role>"`` (checked against
    ``resource_access.<client_id>.roles``). See :ref:`authorization` below.

``ENFORCE_LOCAL_ACTIVE`` (default: ``False``)
    Whether the local ``User.is_active`` flag also gates login/API access, on top of whatever
    ``REQUIRED_GROUPS``/``REQUIRED_ROLES`` decide. See :ref:`authorization` below — **this is a
    behavior change from earlier pyobs-auth versions.**

.. _authorization:

Authorization: claims vs. local ``is_active``
**********************************************

.. warning::
   **Behavior change.** Previous versions of pyobs-auth always refused a resolved user with
   ``is_active=False`` ("Account pending activation"), so every ``USER_RESOLVER`` that minted new
   accounts inactive relied on that as its activation gate. As of this version, ``is_active`` is
   only checked when ``ENFORCE_LOCAL_ACTIVE`` is explicitly set to ``True`` — by default, any
   Keycloak user who authenticates is authorized (unless ``REQUIRED_GROUPS``/``REQUIRED_ROLES``
   says otherwise). **Deployments that rely on the old per-user activation gate must set
   ``ENFORCE_LOCAL_ACTIVE=True`` when upgrading**, or every existing inactive account becomes
   reachable the moment the new version is deployed.

The authorization decision is now claims-based: Keycloak group/role membership, delivered in the
already-validated token, is checked by ``pyobs_auth.authorization.authorize()`` in both
``KeycloakAuthentication`` (API bearer path) and ``CallbackView`` (browser path). With neither
``REQUIRED_GROUPS`` nor ``REQUIRED_ROLES`` set, the gate always passes (today's default, unchanged
so far). When both are set, **both must pass** (AND, not OR). A failed check is refused with "not
authorized", distinct from the "pending activation" message used by the local gate.

``ENFORCE_LOCAL_ACTIVE=True`` layers the old local gate back on top, as a Keycloak-independent
kill switch: an admin can deactivate a specific local ``User`` regardless of their Keycloak group
membership. It composes with the claims gate rather than replacing it - both must pass.

Session refresh
****************

A browser session established via ``CallbackView`` only evaluates claims once, at login. Add
``pyobs_auth.middleware.KeycloakSessionRefreshMiddleware`` to ``MIDDLEWARE`` (after
``AuthenticationMiddleware``) so that once the access token that established the session expires,
it's silently exchanged for a new one via the stored refresh token, the resulting claims are
re-validated and re-run through ``authorize()`` (and, if the token is missing, an
``ENFORCE_LOCAL_ACTIVE``-gated local deactivation is caught too), and the session is ended if
authorization no longer passes. Without this middleware, a revoked Keycloak group/role only takes
effect at the user's next login - bounded only by ``SESSION_COOKIE_AGE``, not by any token
lifetime. This is not automatic - it must be added to each consuming service's ``MIDDLEWARE``
explicitly.

.. warning::
   **Requires a server-side session engine.** ``CallbackView`` stores the Keycloak refresh token
   in the session so this middleware can use it later - a bearer credential that can mint fresh
   access tokens indefinitely. With ``SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"``,
   that would serialize into the browser's cookie (signed, but not encrypted, and readable by the
   client). ``CallbackView`` detects this and refuses to store the refresh token at all rather
   than doing that - the session still works, it just never becomes refreshable, silently falling
   back to "revocation takes effect at next login" for that deployment. Use a server-side engine
   (``django.contrib.sessions.backends.db`` or ``cached_db``) to actually get the benefit of this
   middleware.

A failed refresh only ends the session when Keycloak's token endpoint reports the grant as
genuinely invalid (``error: "invalid_grant"``) - a network failure or a 5xx from Keycloak itself
leaves the session alone and lets the next request retry, rather than mass-logging-out every
active session during a Keycloak outage.

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
