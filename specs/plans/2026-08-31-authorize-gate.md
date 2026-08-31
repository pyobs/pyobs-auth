# Plan: the `authorize()` gate — Keycloak groups/roles authorization in pyobs-auth

Status: **implemented, closed** — merged via #15 ("Centralize authorization via Keycloak
groups/roles") plus a follow-up commit on `develop`, not via a branch built from this plan
directly (see "How this actually landed" below). Kept as a retrospective design record, not a
checklist to execute.

Implements section 1 ("pyobs-auth — the shared gate") of pyobs-core's cross-repo plan
`specs/plans/2026-08-28-shared-authz-keycloak.md`. See that plan and pyobs-core's
`specs/design/shared-authz-keycloak.md` (ADR `0014-centralized-authorization-via-keycloak-groups.md`)
for the cross-repo reasoning; this doc covers only the pyobs-auth-side implementation, as it
actually shipped.

## How this actually landed

This plan was originally drafted and implemented independently on a branch cut from a
stale `develop` (predating #15's merge by about a day), without knowing #15 existed. That
independent branch (PR #16) was closed as superseded once the collision surfaced — the two
implementations covered the same ground but diverged on real design points, and #15's was more
complete. Rather than re-deriving the plan from #16's now-dead branch, this doc was rewritten
against what's actually in `develop`, so it stays useful as a record of the shipped design instead
of a draft that lost.

## Design decisions, as implemented

**Group/role matching is all-of, not any-of.** Every entry in `REQUIRED_GROUPS` must be present
in the token's `groups` claim; every entry in `REQUIRED_ROLES` must be present in
`realm_access.roles`/`resource_access.<client>.roles`. (An earlier draft of this plan proposed
any-of-within-a-list/AND-between-lists; the merged version is simpler — all-of, uniformly — since
no fleet deployment needed the any-of case, and any-of would have been a silent surprise for
whoever set both settings expecting AND.) Identical behavior to any-of for every config in
production today, since `pyobs-archive`/`pyobs-portal`/`pyobs-web-admin` each set exactly one
group.

**`authorize()` raises `AuthorizationError`, not a bool.** `pyobs_auth/authorization.py`. A
malformed `REQUIRED_ROLES` entry (wrong `"kind:"` prefix — not `realm:` or `client:`) raises
`ValueError` rather than silently denying everyone, and both call sites (`authentication.py`,
`views.py`, `middleware.py`) log it via `_logger.exception` before re-raising, so a config typo is
loud, not a silent lockout.

**Checked before user resolution**, in both `KeycloakAuthentication.authenticate` and
`CallbackView.get` — claims-only, so an unauthorized caller never mints a local `User` row.

**`ENFORCE_LOCAL_ACTIVE` (default `False`) is the local kill switch**, composing with (not
replacing) the claims gate — both must pass when both are configured. `docs/source/configuration.rst`
recommends `True` explicitly in every example, to preserve pre-2.1 per-service activation
behavior by default at the documentation level, even though the code default stays `False` for a
bare version bump.

**`KeycloakSessionRefreshMiddleware`** (`pyobs_auth/middleware.py`) — lazy, per-request, only
acts once the access token (tracked via `SESSION_ACCESS_EXPIRES_KEY`) has expired:

- Refreshes via the stored `SESSION_REFRESH_TOKEN_KEY`, re-validates, re-runs `authorize()`
  (and the `ENFORCE_LOCAL_ACTIVE` check), ending the session (`django.contrib.auth.logout`) on
  failure.
- **Outage-tolerant**: only ends the session when Keycloak's token endpoint reports
  `error: "invalid_grant"` specifically (`TokenExchangeError.error_code`, `client.py`) — a
  network failure or 5xx leaves the session alone for the next request to retry, so a Keycloak
  outage doesn't mass-log-out every active session.
- **Refresh-token-rotation race handled**: `invalid_grant` is ambiguous between "genuinely
  revoked" and "a concurrent request already refreshed this same token" (only relevant if the
  realm rotates/revokes refresh tokens on use) — before giving up, re-reads the session fresh from
  its store and adopts it if a concurrent request already won the race.
- **Re-runs the resolver on every refresh**, not just at login, and updates `request.user` with
  the result (logging out if it returns `None`) — so a claim-derived local flag (e.g. portal's
  `is_superuser` synced from a client role) picks up a Keycloak-side change within one
  access-token lifetime, and the *current* request sees it too.

**Refresh token storage is conditional on a server-side `SESSION_ENGINE`.** `CallbackView`
detects a cookie-backed engine (`signed_cookies`) and refuses to store the refresh token at all —
storing a credential that can mint fresh access tokens indefinitely into a signed-but-unencrypted,
client-readable cookie would hand it to the browser. That session simply isn't refreshable
(the middleware is a no-op for it), falling back to "revocation takes effect at next login," with
a logged warning naming the deployment gap. This is why `pyobs-web-admin`'s cutover
(`pyobs_web_admin/settings.py`) switched `SESSION_ENGINE` from `signed_cookies` to `db`.

## Per-service cutovers

Not part of this repo — see each service's own commit for its actual cutover
(`pyobs-archive`, `pyobs-portal`, `pyobs-web-admin`, each on `develop`):

- `PYOBS_AUTH['REQUIRED_GROUPS']` set to that service's group, `ENFORCE_LOCAL_ACTIVE=True`.
- Resolvers mint `is_active=True` (the claims gate is now the check, not local activation).
- `pyobs-portal` additionally syncs `is_superuser` (never `is_staff`) from the `portal-admin`
  client role on every resolve — reading the client id from `PYOBS_AUTH['CLIENT_ID']` rather than
  a hardcoded name, since `resource_access` is keyed by each deployment's own Keycloak client id
  (this fleet's actual client for portal is `monets-observe`, not `portal` — see the site-config
  repos' own topology docs, kept out of this public repo deliberately).
- `pyobs-archive` additionally migrated already-existing inactive Keycloak-linked users to active
  via a data migration (`0007_activate_keycloak_linked_users.py`), since the resolver-time flip
  above only covers newly-minted accounts going forward. `pyobs-portal`/`pyobs-web-admin` don't
  have an equivalent migration as of this writing — worth checking whether that's deliberate
  (few/no pre-existing inactive Keycloak-linked accounts there) or a gap.
- All three still declare `pyobs-auth>=2.0.0` in `pyproject.toml` and gate the new middleware
  behind a TODO pending an actual `2.1.0` release — `REQUIRED_GROUPS`/`ENFORCE_LOCAL_ACTIVE`
  being present in a `PYOBS_AUTH` dict is a harmless no-op against pyobs-auth 2.0.0 (unrecognized
  keys are just ignored by `get_settings()`), so this is safe to have merged ahead of the release,
  but the release itself (`do-python-release`, bumping to 2.1.0) is still open.

## Not in this plan (boundary notes)

- Service-to-service (client-credentials) authorization — unchanged, out of scope per the design
  doc.
- Keycloak Authorization Services (UMA) — not adopted.
- Per-request revocation checks via the Keycloak Admin REST API — documented option only, not
  built.
