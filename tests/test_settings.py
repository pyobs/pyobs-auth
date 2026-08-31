import pytest

from pyobs_auth.settings import ImproperlyConfiguredError, get_settings


@pytest.mark.django_db
def test_get_settings_reads_django_setting():
    settings = get_settings()
    assert settings.server_url == "https://keycloak.example.org"
    assert settings.realm == "pyobs"
    assert settings.client_id == "archive"
    assert settings.issuer == "https://keycloak.example.org/realms/pyobs"
    assert settings.discovery_url == "https://keycloak.example.org/realms/pyobs/.well-known/openid-configuration"
    assert settings.expected_audience == "archive"


def test_missing_required_key_raises(settings):
    settings.PYOBS_AUTH = {"SERVER_URL": "https://keycloak.example.org", "REALM": "pyobs"}
    with pytest.raises(ImproperlyConfiguredError, match="CLIENT_ID"):
        get_settings()


def test_missing_setting_entirely_raises(settings):
    settings.PYOBS_AUTH = None
    with pytest.raises(ImproperlyConfiguredError):
        get_settings()


def test_resolve_user_callable_requires_user_resolver():
    from pyobs_auth.settings import KeycloakSettings

    bare = KeycloakSettings(server_url="https://keycloak.example.org", realm="pyobs", client_id="archive")
    with pytest.raises(ImproperlyConfiguredError):
        bare.resolve_user_callable()


def test_resolve_user_callable_imports_dotted_path(keycloak_settings):
    from tests.helpers import resolve_user

    assert keycloak_settings.resolve_user_callable() is resolve_user


def test_required_groups_and_roles_default_to_empty_tuple():
    settings = get_settings()
    assert settings.required_groups == ()
    assert settings.required_roles == ()
    assert settings.enforce_local_active is False


def test_required_groups_accepts_a_list(settings):
    from django.conf import settings as django_settings

    settings.PYOBS_AUTH = {**django_settings.PYOBS_AUTH, "REQUIRED_GROUPS": ["/pyobs-archive", "/pyobs-other"]}
    assert get_settings().required_groups == ("/pyobs-archive", "/pyobs-other")


def test_required_groups_given_as_a_bare_string_is_not_split_into_characters(settings):
    from django.conf import settings as django_settings

    settings.PYOBS_AUTH = {**django_settings.PYOBS_AUTH, "REQUIRED_GROUPS": "/pyobs-archive"}
    assert get_settings().required_groups == ("/pyobs-archive",)


def test_required_roles_given_as_a_bare_string_is_not_split_into_characters(settings):
    from django.conf import settings as django_settings

    settings.PYOBS_AUTH = {**django_settings.PYOBS_AUTH, "REQUIRED_ROLES": "realm:pyobs-admin"}
    assert get_settings().required_roles == ("realm:pyobs-admin",)


@pytest.mark.parametrize("value", [True, "true", "True", "1", "yes", "YES"])
def test_enforce_local_active_truthy_values(settings, value):
    from django.conf import settings as django_settings

    settings.PYOBS_AUTH = {**django_settings.PYOBS_AUTH, "ENFORCE_LOCAL_ACTIVE": value}
    assert get_settings().enforce_local_active is True


@pytest.mark.parametrize("value", [False, "false", "False", "0", "", "no"])
def test_enforce_local_active_falsy_values_including_the_string_false(settings, value):
    from django.conf import settings as django_settings

    settings.PYOBS_AUTH = {**django_settings.PYOBS_AUTH, "ENFORCE_LOCAL_ACTIVE": value}
    assert get_settings().enforce_local_active is False
