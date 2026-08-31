# Plans

Implementation plans, checklist-style. Newest at the bottom.

- [2026-08-31-authorize-gate.md](2026-08-31-authorize-gate.md) — the `authorize()` gate: Keycloak
  groups/roles authorization (`REQUIRED_GROUPS`/`REQUIRED_ROLES`/`ENFORCE_LOCAL_ACTIVE`), wired
  into `KeycloakAuthentication`/`CallbackView`, plus a session-refresh middleware for revocation
  freshness. Implements section 1 of pyobs-core's `specs/plans/2026-08-28-shared-authz-keycloak.md`
  (design: pyobs-core's `specs/design/shared-authz-keycloak.md`, ADR `0014`). **implemented,
  closed** — landed via #15, not this doc's original branch; kept as a retrospective design
  record (issue #823)
