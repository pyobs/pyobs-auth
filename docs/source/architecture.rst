Architecture
############

*pyobs-auth* is a library, not a service — it's installed into other pyobs web apps
(pyobs-archive, pyobs-portal, pyobs-web-admin) so they share one authentication implementation
instead of each rolling their own against Keycloak. See pyobs-core's
`specs/design/shared-auth-keycloak.md
<https://github.com/pyobs/pyobs-core/blob/develop/specs/design/shared-auth-keycloak.md>`_ for the
full design history and the problem this replaced (each service previously had its own
uncoordinated auth backend).

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
- ``pyobs_auth.views``/``pyobs_auth.urls`` — the browser-facing login redirect + callback views
  for the PKCE flow (session-based), plus ``LogoutView``, which ends the Keycloak SSO session via
  RP-Initiated Logout only for sessions that actually came from Keycloak — a plain local-password
  session gets an ordinary local logout, so the host app's one "Log out" link/URL works correctly
  either way without knowing how the user signed in.

See :doc:`api` for the full class reference.

One-click IdP login
********************

``IDP_HINT``/``IDP_LABEL`` (see :doc:`configuration`) implement Keycloak's ``kc_idp_hint``
authorization-endpoint parameter: when set, Keycloak skips its own login/IdP-selection page and
redirects straight to that identity provider. Each host service's login page renders a dual-button
pattern when a hint is configured — "Log in with ``<hinted IdP>``" (default) and "Log in with
local Keycloak account" (via a present-but-empty ``?idp_hint=``) — keeping the local-account path
reachable rather than hiding it behind the hint.
