from dataclasses import replace

from pyobs_auth.authorization import authorize


def test_no_settings_always_passes(keycloak_settings, make_claims):
    claims = make_claims()
    assert authorize(claims, keycloak_settings) is True


def test_required_group_matches(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_groups=("/pyobs-archive",))
    claims = make_claims(groups=["/pyobs-archive", "/something-else"])
    assert authorize(claims, settings) is True


def test_required_group_no_match(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_groups=("/pyobs-archive",))
    claims = make_claims(groups=["/something-else"])
    assert authorize(claims, settings) is False


def test_required_group_missing_claim_fails_closed(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_groups=("/pyobs-archive",))
    claims = make_claims()  # no "groups" key at all
    assert authorize(claims, settings) is False


def test_required_group_any_of_multiple_is_enough(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_groups=("/pyobs-archive", "/pyobs-portal"))
    claims = make_claims(groups=["/pyobs-portal"])
    assert authorize(claims, settings) is True


def test_required_realm_role_matches(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_roles=("realm:pyobs-admin",))
    claims = make_claims(realm_access={"roles": ["pyobs-admin", "other"]})
    assert authorize(claims, settings) is True


def test_required_realm_role_no_match(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_roles=("realm:pyobs-admin",))
    claims = make_claims(realm_access={"roles": ["other"]})
    assert authorize(claims, settings) is False


def test_required_client_role_matches(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_roles=("client:portal:portal-admin",))
    claims = make_claims(resource_access={"portal": {"roles": ["portal-admin"]}})
    assert authorize(claims, settings) is True


def test_required_client_role_no_match_wrong_client(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_roles=("client:portal:portal-admin",))
    claims = make_claims(resource_access={"other-client": {"roles": ["portal-admin"]}})
    assert authorize(claims, settings) is False


def test_required_roles_missing_claims_fail_closed(keycloak_settings, make_claims):
    settings = replace(keycloak_settings, required_roles=("realm:pyobs-admin",))
    claims = make_claims()  # no realm_access/resource_access at all
    assert authorize(claims, settings) is False


def test_both_group_and_role_required_is_and(keycloak_settings, make_claims):
    settings = replace(
        keycloak_settings,
        required_groups=("/pyobs-portal",),
        required_roles=("client:portal:portal-admin",),
    )

    # group only -> fails the role half
    assert authorize(make_claims(groups=["/pyobs-portal"]), settings) is False
    # role only -> fails the group half
    assert authorize(make_claims(resource_access={"portal": {"roles": ["portal-admin"]}}), settings) is False
    # both -> passes
    assert (
        authorize(
            make_claims(groups=["/pyobs-portal"], resource_access={"portal": {"roles": ["portal-admin"]}}),
            settings,
        )
        is True
    )
