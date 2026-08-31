"""Claims-based authorization: "may this token's user use this service, and with which role."

Separate from validation.py (is the token genuine) and settings.py (config surface) - this module
only decides pass/refuse given already-validated claims. See pyobs-core's shared-authz design doc
(specs/design/shared-authz-keycloak.md) for the full reasoning.

Semantics:
- Within REQUIRED_GROUPS: any one matching group is enough (an access list, not a checklist).
- Within REQUIRED_ROLES: same, any one matching role is enough.
- Between REQUIRED_GROUPS and REQUIRED_ROLES, when both are set: AND. REQUIRED_GROUPS is the
  coarse "may use this service at all" gate; REQUIRED_ROLES is a stricter sub-gate layered on top
  (e.g. an admin-only deployment), not an alternative path around the group check.
- Either setting unset (empty) always passes its half of the check - this is what makes
  "no settings set at all" a no-op gate.

REQUIRED_ROLES entries: "realm:<role>" for a realm role, or "client:<client_id>:<role>" for a
client role - matching claims.resource_access.<client_id>.roles.
"""

from __future__ import annotations

from typing import Any

from .settings import KeycloakSettings


def _has_required_group(claims: dict[str, Any], required_groups: tuple[str, ...]) -> bool:
    if not required_groups:
        return True
    groups = claims.get("groups") or []
    return any(group in groups for group in required_groups)


def _matches_role(claims: dict[str, Any], role_spec: str) -> bool:
    kind, _, rest = role_spec.partition(":")
    if kind == "realm":
        roles = (claims.get("realm_access") or {}).get("roles") or []
        return rest in roles
    if kind == "client":
        client_id, _, role = rest.partition(":")
        roles = ((claims.get("resource_access") or {}).get(client_id) or {}).get("roles") or []
        return role in roles
    return False


def _has_required_role(claims: dict[str, Any], required_roles: tuple[str, ...]) -> bool:
    if not required_roles:
        return True
    return any(_matches_role(claims, role_spec) for role_spec in required_roles)


def authorize(claims: dict[str, Any], settings: KeycloakSettings) -> bool:
    """True if validated `claims` satisfy `settings.required_groups`/`required_roles`."""
    return _has_required_group(claims, settings.required_groups) and _has_required_role(claims, settings.required_roles)
