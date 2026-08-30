"""Claims-based authorization gate: Keycloak group/role membership as the authorization source
of truth, replacing per-service local `is_active` activation. See pyobs-core's
`specs/design/shared-authz-keycloak.md` and ADR `0014-centralized-authorization-via-keycloak-groups.md`
for the reasoning.

Neither `REQUIRED_GROUPS` nor `REQUIRED_ROLES` set -> `authorize()` always passes (opt-in gate,
current behavior unchanged). Both set -> both must pass (AND, not OR) - there's no fleet use case
today that needs "either this group or that role", and OR would be a silent surprise for whoever
sets both expecting an AND.
"""

from __future__ import annotations

from typing import Any

from .settings import KeycloakSettings


class AuthorizationError(Exception):
    pass


def _has_required_groups(claims: dict[str, Any], required_groups: tuple[str, ...]) -> bool:
    groups = set(claims.get("groups") or [])
    return all(group in groups for group in required_groups)


def _has_required_roles(claims: dict[str, Any], required_roles: tuple[str, ...]) -> bool:
    realm_roles = set((claims.get("realm_access") or {}).get("roles") or [])
    resource_access = claims.get("resource_access") or {}

    for required in required_roles:
        kind, _, name = required.partition(":")
        if kind == "realm":
            if name not in realm_roles:
                return False
        elif kind == "client":
            client_id, _, role = name.partition(":")
            client_roles = set((resource_access.get(client_id) or {}).get("roles") or [])
            if role not in client_roles:
                return False
        else:
            raise ValueError(
                f"malformed PYOBS_AUTH['REQUIRED_ROLES'] entry {required!r} -"
                " expected 'realm:<role>' or 'client:<client_id>:<role>'"
            )
    return True


def authorize(claims: dict[str, Any], settings: KeycloakSettings) -> None:
    """Raise AuthorizationError unless `claims` satisfies every configured REQUIRED_GROUPS entry
    (full group paths, e.g. `/pyobs-archive`) and every configured REQUIRED_ROLES entry (realm
    roles as `realm:<role>`, client roles as `client:<client_id>:<role>`).
    """
    if not settings.required_groups and not settings.required_roles:
        return

    if not _has_required_groups(claims, settings.required_groups):
        raise AuthorizationError("not authorized")
    if not _has_required_roles(claims, settings.required_roles):
        raise AuthorizationError("not authorized")
