Architecture
############

*pyobs-auth* is a library, not a service — it's installed into other pyobs web apps
(pyobs-archive, pyobs-portal, pyobs-web-admin) so they share one authentication implementation
instead of each rolling their own against Keycloak, which is what each service did before this
library existed.

Single issuer, by design
***************************

Every service trusts exactly **one** Keycloak realm — there's no support for multiple issuers.
Any upstream identity provider (an institute's SSO, a self-hosted ``observation-portal``, ...) is
meant to be brokered *behind* that Keycloak instance (configured in Keycloak's own admin console,
not in pyobs-auth), not validated directly by this library.

The pieces
**********

- ``pyobs_auth.client.KeycloakClient`` — OIDC discovery, authorization-code + PKCE for user login,
  client-credentials grant for service-to-service calls, refresh.
- ``pyobs_auth.validation.TokenValidator`` — stateless bearer-token validation against the
  realm's JWKS (signature, issuer, audience, expiry). No per-request network round-trip to
  Keycloak.
- ``pyobs_auth.authentication.KeycloakAuthentication`` — a DRF ``BaseAuthentication`` class wiring
  the validator into ``REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']``, additive alongside a
  service's existing authentication classes (e.g. DRF ``TokenAuthentication`` for
  service-to-service calls).
- ``pyobs_auth.authorization.authorize`` — the claims-based authorization decision
  (``REQUIRED_GROUPS``/``REQUIRED_ROLES``), called from both ``KeycloakAuthentication`` and
  ``CallbackView`` before either resolves a local user, so an unauthorized caller never mints a
  ``User`` row. Raises ``AuthorizationError`` rather than returning a bool. See
  :doc:`configuration`.
- ``pyobs_auth.views``/``pyobs_auth.urls`` — the browser-facing login redirect + callback views
  for the PKCE flow (session-based), plus ``LogoutView``, which ends the Keycloak SSO session via
  RP-Initiated Logout only for sessions that actually came from Keycloak — a plain local-password
  session gets an ordinary local logout, so the host app's one "Log out" link/URL works correctly
  either way without knowing how the user signed in.
- ``pyobs_auth.middleware.KeycloakSessionRefreshMiddleware`` — keeps a browser session's
  authorization decision fresh between logins: silently refreshes the access token once it
  expires and re-runs ``authorize()``, tolerating a Keycloak outage (only ``invalid_grant``
  ends the session) and a benign refresh-token-rotation race between concurrent requests. Requires
  a server-side ``SESSION_ENGINE`` — ``CallbackView`` refuses to store the refresh token in a
  cookie-backed session. See :doc:`installation`.

See :doc:`api` for the full class reference.

One-click IdP login
********************

``IDP_HINT``/``IDP_LABEL`` (see :doc:`configuration`) implement Keycloak's ``kc_idp_hint``
authorization-endpoint parameter: when set, Keycloak skips its own login/IdP-selection page and
redirects straight to that identity provider. Each host service's login page renders a dual-button
pattern when a hint is configured — "Log in with ``<hinted IdP>``" (default) and "Log in with
local Keycloak account" (via a present-but-empty ``?idp_hint=``) — keeping the local-account path
reachable rather than hiding it behind the hint.
