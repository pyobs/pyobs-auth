from __future__ import annotations

import pytest

from pyobs_auth.authorization import AuthorizationError, authorize
from pyobs_auth.settings import KeycloakSettings

BASE = dict(server_url="https://keycloak.example.org", realm="pyobs", client_id="archive")


def test_authorize_passes_when_no_settings_configured():
    settings = KeycloakSettings(**BASE)
    authorize({}, settings)  # no exception


def test_authorize_passes_when_required_group_present():
    settings = KeycloakSettings(**BASE, required_groups=("/pyobs-archive",))
    authorize({"groups": ["/pyobs-archive", "/something-else"]}, settings)


def test_authorize_raises_when_required_group_missing():
    settings = KeycloakSettings(**BASE, required_groups=("/pyobs-archive",))
    with pytest.raises(AuthorizationError):
        authorize({"groups": ["/some-other-group"]}, settings)


def test_authorize_raises_when_groups_claim_absent():
    settings = KeycloakSettings(**BASE, required_groups=("/pyobs-archive",))
    with pytest.raises(AuthorizationError):
        authorize({}, settings)


def test_authorize_passes_with_realm_role():
    settings = KeycloakSettings(**BASE, required_roles=("realm:pyobs-admin",))
    authorize({"realm_access": {"roles": ["pyobs-admin", "other"]}}, settings)


def test_authorize_raises_when_realm_role_missing():
    settings = KeycloakSettings(**BASE, required_roles=("realm:pyobs-admin",))
    with pytest.raises(AuthorizationError):
        authorize({"realm_access": {"roles": ["other"]}}, settings)


def test_authorize_passes_with_client_role():
    settings = KeycloakSettings(**BASE, required_roles=("client:portal:portal-admin",))
    authorize({"resource_access": {"portal": {"roles": ["portal-admin"]}}}, settings)


def test_authorize_raises_when_client_role_missing():
    settings = KeycloakSettings(**BASE, required_roles=("client:portal:portal-admin",))
    with pytest.raises(AuthorizationError):
        authorize({"resource_access": {"portal": {"roles": ["some-other-role"]}}}, settings)


def test_authorize_raises_when_client_missing_from_resource_access():
    settings = KeycloakSettings(**BASE, required_roles=("client:portal:portal-admin",))
    with pytest.raises(AuthorizationError):
        authorize({"resource_access": {"archive": {"roles": ["portal-admin"]}}}, settings)


def test_authorize_raises_on_malformed_role_without_colon():
    settings = KeycloakSettings(**BASE, required_roles=("portal-admin",))
    with pytest.raises(ValueError, match="malformed"):
        authorize({}, settings)


def test_authorize_raises_on_unknown_role_kind():
    settings = KeycloakSettings(**BASE, required_roles=("resource:portal:portal-admin",))
    with pytest.raises(ValueError, match="malformed"):
        authorize({}, settings)


def test_authorize_requires_both_groups_and_roles_when_both_set():
    settings = KeycloakSettings(
        **BASE,
        required_groups=("/pyobs-portal",),
        required_roles=("client:portal:portal-admin",),
    )
    # group ok, role missing -> still fails (AND, not OR)
    with pytest.raises(AuthorizationError):
        authorize(
            {"groups": ["/pyobs-portal"], "resource_access": {"portal": {"roles": []}}},
            settings,
        )
    # role ok, group missing -> still fails
    with pytest.raises(AuthorizationError):
        authorize(
            {"groups": [], "resource_access": {"portal": {"roles": ["portal-admin"]}}},
            settings,
        )
    # both ok -> passes
    authorize(
        {"groups": ["/pyobs-portal"], "resource_access": {"portal": {"roles": ["portal-admin"]}}},
        settings,
    )
