# Plan: the `authorize()` gate — Keycloak groups/roles authorization in pyobs-auth

Status: implemented, pending PR review (branch `feat/authorize-gate`).

Implements section 1 ("pyobs-auth — the shared gate") of pyobs-core's cross-repo plan
`specs/plans/2026-08-28-shared-authz-keycloak.md`. See that plan and pyobs-core's
`specs/design/shared-authz-keycloak.md` (ADR `0014-centralized-authorization-via-keycloak-groups.md`)
for the full reasoning; this doc only elaborates the pyobs-auth-side implementation, grounded in
the actual current code (`pyobs_auth/settings.py`, `authentication.py`, `views.py`, `client.py`,
`validation.py`).

Keycloak-side prerequisites (realm groups, the `groups` client scope/mapper, a `portal-admin`
client role on the portal client) are already done for at least one fleet — see the relevant
site-config repo's own `specs/design/keycloak-service-topology.md` for exact client/group names,
which are deployment-specific and don't belong in this repo.

## 0. Open design question — needs a decision before implementation starts

The design doc doesn't pin down how `REQUIRED_GROUPS` and `REQUIRED_ROLES` combine when both are
set. Proposed semantics, matching "may this person use service X, and with which role":

- Within `REQUIRED_GROUPS`: **any** listed group is enough (a user only needs to be in one).
- Within `REQUIRED_ROLES`: same, **any** listed role is enough.
- Between the two settings, if **both** are set: **AND** — the claims must satisfy both the group
  check and the role check. Rationale: `REQUIRED_GROUPS` is the coarse "may use this service at
  all" gate; `REQUIRED_ROLES` is meant for a *stricter* sub-gate (e.g. an admin-only deployment of
  a service), not an alternative path around the group check.
- Either setting unset ⇒ that half of the check always passes (existing "no settings ⇒ always
  pass" behavior extends per-setting, not just when both are empty).

This governs the actual matching logic below — confirm before I write `authorization.py`, since
it's a security-relevant decision, not just an implementation detail.

**Resolved**: confirmed as proposed above, implemented as-is in `authorization.py`.

## 1. `KeycloakSettings` (`settings.py`)

- [x] Add fields: `required_groups: tuple[str, ...] = ()`, `required_roles: tuple[str, ...] = ()`,
      `enforce_local_active: bool = False`.
- [x] `get_settings()`: read `PYOBS_AUTH["REQUIRED_GROUPS"]`, `["REQUIRED_ROLES"]`,
      `["ENFORCE_LOCAL_ACTIVE"]` (all optional, same pattern as `SCOPES`/`IDP_HINT` today).
- [x] `REQUIRED_ROLES` entry syntax: `"realm:<role>"` or `"client:<client_id>:<role>"` (matches the
      pyobs-core plan's example `client:portal:portal-admin`; the syntax is generic, the actual
      client id is per-deployment config, set outside this repo).
- [x] `tests/test_settings.py`: parsing of all three new keys, defaults when unset.

## 2. New `pyobs_auth/authorization.py`

- [x] `authorize(claims: dict, settings: KeycloakSettings) -> bool`, implementing the semantics
      from §0:
  - Groups: `claims.get("groups", [])` (full paths, e.g. `/pyobs-archive`) intersected with
    `settings.required_groups`.
  - Realm roles: `claims.get("realm_access", {}).get("roles", [])`.
  - Client roles: `claims.get("resource_access", {}).get(client_id, {}).get("roles", [])` — parsed
    out of each `"client:<client_id>:<role>"` entry in `required_roles`.
  - No claims-shape assumptions beyond what Keycloak's default mappers produce — a missing
    `groups`/`realm_access`/`resource_access` key means "no groups/roles", not an error.
- [x] `tests/test_authorization.py`: no settings ⇒ pass; `REQUIRED_GROUPS` match/no-match;
      `REQUIRED_ROLES` realm-role and client-role match/no-match; both set (AND per §0); malformed/
      missing claim keys don't raise.

## 3. Wire into `KeycloakAuthentication.authenticate` (`authentication.py`)

Current flow (lines 49-61): validate → resolve user → reject if `not user.is_active`.

- [x] Call `authorize(claims, settings)` **right after `validator.validate(token)`, before
      `user_resolver(claims)`** — claims-only check, no need to mint/touch a local `User` row for
      someone who isn't authorized at all. Raise `AuthenticationFailed("not authorized")` on
      failure (distinct message from today's "Account pending activation", per the pyobs-core
      plan).
- [x] The existing `if not user.is_active: raise ...` becomes conditional on
      `settings.enforce_local_active` (default `False` ⇒ that check no longer runs at all).
- [x] `tests/test_authentication.py`: extend `make_claims`/`keycloak_settings` fixtures (or add
      variants) with `required_groups`/`required_roles`; cases: claims lacking required group/role
      → `AuthenticationFailed("not authorized")`; no settings ⇒ unchanged passthrough;
      `enforce_local_active=True` + inactive user + authorized claims → still refused (old
      behavior preserved as opt-in); `enforce_local_active=False` (default) + inactive user +
      authorized claims → passes (this is the behavior change to actually test for).

## 4. Wire into `CallbackView` (`views.py`) + store the refresh token

Current flow (lines 83-97): validate access token → resolve user → reject if inactive → `login()`.
Only `id_token` is kept in session (`SESSION_ID_TOKEN_KEY`); `refresh_token` from `tokens` is
discarded.

- [x] Same `authorize()` call, same placement (before `user_resolver`), same conditional
      `enforce_local_active` gate, using `_error_response(request, "not authorized")` for the
      styled refusal page instead of DRF's exception.
- [x] New session keys in `views.py`: `SESSION_REFRESH_TOKEN_KEY`, and one more to carry the
      access token's expiry forward without persisting the raw access token —
      `SESSION_ACCESS_TOKEN_EXP_KEY`, set from the already-validated `claims["exp"]` (no new
      decoding needed; `validate()` already requires `exp` to be present).
- [x] Store both alongside the existing `id_token` set (same post-`login()` placement, same
      rotation-safety comment already there).
- [x] `tests/test_views.py`: successful callback stores `refresh_token`/access-token-exp in
      session; refused (unauthorized) callback does not call `login()` and does not store any
      session keys; `enforce_local_active` interplay mirrored from §3.

## 5. New middleware: `pyobs_auth/middleware.py` — session refresh + re-authorization

This is the piece that actually bounds revocation to one access-token lifetime instead of
`SESSION_COOKIE_AGE` (design doc, "Revocation model and freshness"). Runs on every request; only
acts on sessions that went through `CallbackView` (i.e. have the session keys from §4) — a
locally-authenticated (`createsuperuser`/Django-admin) session has none of them and is a no-op.

- [x] `KeycloakSessionRefreshMiddleware` (standard `get_response`-style Django middleware):
  1. No `SESSION_REFRESH_TOKEN_KEY`/`SESSION_ACCESS_TOKEN_EXP_KEY` in session ⇒ return
     immediately (not a Keycloak SSO session, or pre-cutover session predating this middleware).
  2. `time.time() < exp` ⇒ still fresh, return immediately (this is the common case — no
     Keycloak round trip per request).
  3. Otherwise: `KeycloakClient(settings).refresh(refresh_token=...)`. On `TokenExchangeError`
     (refresh token itself expired/revoked) → force logout (`django.contrib.auth.logout`), clear
     session, let the request continue unauthenticated (don't hard-fail the request — same
     posture as any expired-session request today).
  4. Re-validate the new `access_token` via `TokenValidator.validate()`, then re-run
     `authorize()` on the fresh claims. Either failing (invalid token, or a group/role that was
     revoked since login) → force logout, same as step 3.
  5. On success: re-run `settings.resolve_user_callable()(claims)` — the design doc calls for
     locally-synced flags (e.g. portal's `is_superuser` from `portal-admin`) to "re-derive on the
     same refresh cycle," and the per-service resolver is the only place that sync logic lives.
     This is a **new requirement pyobs-auth must actively drive**, not just a side effect — it
     isn't spelled out as a pyobs-auth checklist item in the pyobs-core plan, but the design doc's
     revocation-freshness section depends on it happening somewhere, and pyobs-auth's middleware
     is the only place positioned to do it outside the login path.
  6. Update session: new `exp`, and `refresh_token`/`id_token` if Keycloak rotated them (some
     realm/client settings issue a new refresh token on every refresh — always overwrite if
     present in the response, keep the old one if absent).
- [x] Docs: services must add this to their `MIDDLEWARE` list, after
      `django.contrib.sessions.middleware.SessionMiddleware` and
      `django.contrib.auth.middleware.AuthenticationMiddleware` (needs both the session and
      `request.user`/`logout()`).
- [x] `tests/test_middleware.py` (new): fresh session (exp in future) ⇒ no HTTP calls made
      (assert via `responses` that no token-endpoint request happened); expired session + valid
      refresh ⇒ session updated, request proceeds authenticated; expired session + refresh
      failure (mocked `TokenExchangeError`) ⇒ logged out; expired session + refresh succeeds but
      `authorize()` now fails (claims missing the required group) ⇒ logged out even though the
      refresh itself succeeded; non-Keycloak session (no relevant session keys) ⇒ untouched.

## 6. Docs

- [x] `docs/source/configuration.rst`: document `REQUIRED_GROUPS`, `REQUIRED_ROLES`,
      `ENFORCE_LOCAL_ACTIVE` in the existing per-setting list (same style as `IDP_HINT` etc.), plus
      the `REQUIRED_ROLES` string syntax.
  - [x] Explicitly document the "Deployment note" and "Failure mode to avoid" callouts already
        written into the pyobs-core plan's section 1 (reproducing pre-authz behavior via
        `ENFORCE_LOCAL_ACTIVE=True`; the silent-drop-of-the-activation-gate risk on a code-only
        upgrade with no settings change).
- [x] `docs/source/installation.rst` (or wherever `MIDDLEWARE` is currently documented, if
      anywhere — check before adding a new section): add
      `KeycloakSessionRefreshMiddleware` installation instructions.
- [x] `README.md`: brief mention if it currently lists `MIDDLEWARE`/settings (check current
      content before editing — avoid duplicating what's already in configuration.rst).

## 7. Release

- [ ] Per repo conventions (`do-python-release`).

## Not in this plan (boundary notes)

- Per-service cutovers (`REQUIRED_GROUPS`/`REQUIRED_ROLES` config values, `is_active=True`
  minting, `is_superuser` sync in each service's own `USER_RESOLVER`) — section 2/3 of the
  pyobs-core plan, done per service, not here.
- Service-to-service (client-credentials) authorization — unchanged, out of scope per the design
  doc.
- Keycloak Authorization Services (UMA) — not adopted.
- Per-request revocation checks via the Keycloak Admin REST API — documented option only, not
  built.
