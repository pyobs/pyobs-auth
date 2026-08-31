"""Config surface for pyobs-auth: one shared Keycloak realm, one client per service.

Read from the Django ``PYOBS_AUTH`` setting, e.g.::

    PYOBS_AUTH = {
        "SERVER_URL": "https://keycloak.example.org",
        "REALM": "pyobs",
        "CLIENT_ID": "archive",
        "CLIENT_SECRET": os.getenv("KEYCLOAK_CLIENT_SECRET"),
        "REDIRECT_URI": "https://archive.example.org/accounts/keycloak/callback/",
        "POST_LOGOUT_REDIRECT_URI": "https://archive.example.org/",
        # dotted path to a callable(claims: dict) -> django.contrib.auth.models.User
        "USER_RESOLVER": "pyobs_archive.authentication.keycloak.resolve_user",
        # optional: gate on Keycloak group/role claims instead of (or in addition to) local
        # is_active - see authorization.py
        "REQUIRED_GROUPS": ["/pyobs-archive"],
        "REQUIRED_ROLES": ["client:archive:archive-admin"],
        "ENFORCE_LOCAL_ACTIVE": False,
    }
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import import_module
from typing import Any


@dataclass(frozen=True)
class KeycloakSettings:
    server_url: str
    realm: str
    client_id: str
    client_secret: str | None = None
    audience: str | None = None
    redirect_uri: str | None = None
    post_logout_redirect_uri: str | None = None
    scopes: tuple[str, ...] = field(default_factory=lambda: ("openid", "profile", "email"))
    user_resolver: str | None = None
    idp_hint: str | None = None
    required_groups: tuple[str, ...] = ()
    required_roles: tuple[str, ...] = ()
    enforce_local_active: bool = False

    @property
    def issuer(self) -> str:
        return f"{self.server_url.rstrip('/')}/realms/{self.realm}"

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def expected_audience(self) -> str:
        return self.audience or self.client_id

    def resolve_user_callable(self) -> Callable[[dict[str, Any]], Any]:
        if not self.user_resolver:
            raise ImproperlyConfiguredError(
                "PYOBS_AUTH['USER_RESOLVER'] is not set - pyobs-auth needs a"
                " callable(claims: dict) -> User to map a validated token to a local user"
            )
        module_path, _, attr = self.user_resolver.rpartition(".")
        if not module_path:
            raise ImproperlyConfiguredError(f"PYOBS_AUTH['USER_RESOLVER'] is not a dotted path: {self.user_resolver!r}")
        module = import_module(module_path)
        return getattr(module, attr)


class ImproperlyConfiguredError(Exception):
    pass


def get_settings() -> KeycloakSettings:
    """Build KeycloakSettings from Django's PYOBS_AUTH setting."""
    from django.conf import settings as django_settings

    raw: dict[str, Any] | None = getattr(django_settings, "PYOBS_AUTH", None)
    if not raw:
        raise ImproperlyConfiguredError("PYOBS_AUTH setting is missing")

    missing = [key for key in ("SERVER_URL", "REALM", "CLIENT_ID") if not raw.get(key)]
    if missing:
        raise ImproperlyConfiguredError(f"PYOBS_AUTH is missing required key(s): {', '.join(missing)}")

    return KeycloakSettings(
        server_url=raw["SERVER_URL"],
        realm=raw["REALM"],
        client_id=raw["CLIENT_ID"],
        client_secret=raw.get("CLIENT_SECRET"),
        audience=raw.get("AUDIENCE"),
        redirect_uri=raw.get("REDIRECT_URI"),
        post_logout_redirect_uri=raw.get("POST_LOGOUT_REDIRECT_URI"),
        scopes=tuple(raw.get("SCOPES", ("openid", "profile", "email"))),
        user_resolver=raw.get("USER_RESOLVER"),
        idp_hint=raw.get("IDP_HINT"),
        required_groups=tuple(raw.get("REQUIRED_GROUPS", ())),
        required_roles=tuple(raw.get("REQUIRED_ROLES", ())),
        enforce_local_active=bool(raw.get("ENFORCE_LOCAL_ACTIVE", False)),
    )
