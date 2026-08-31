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
    assert settings.required_groups == ()
    assert settings.required_roles == ()
    assert settings.enforce_local_active is False


def test_get_settings_reads_authorization_keys(settings):
    settings.PYOBS_AUTH = {
        **settings.PYOBS_AUTH,
        "REQUIRED_GROUPS": ["/pyobs-archive"],
        "REQUIRED_ROLES": ["client:archive:archive-admin"],
        "ENFORCE_LOCAL_ACTIVE": True,
    }
    parsed = get_settings()
    assert parsed.required_groups == ("/pyobs-archive",)
    assert parsed.required_roles == ("client:archive:archive-admin",)
    assert parsed.enforce_local_active is True


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
