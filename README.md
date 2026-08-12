# pyobs-auth

Shared Keycloak/OIDC authentication client for pyobs web services (`pyobs-archive`,
`pyobs-robotic-backend`, and future services), so each one doesn't reimplement OIDC discovery,
token validation, and user mapping on its own.

Single issuer only, by design: every service trusts exactly one Keycloak realm. Any upstream
identity provider (an institute's SSO, a self-hosted `observation-portal`, ...) is meant to be
brokered *behind* that Keycloak instance, not validated directly by this library - see
`pyobs-core`'s `specs/design/shared-auth-keycloak.md` for the full reasoning.

## What's here

- `pyobs_auth.client.KeycloakClient` - OIDC discovery, authorization-code + PKCE for user login,
  client-credentials grant for service-to-service calls, refresh.
- `pyobs_auth.validation.TokenValidator` - stateless bearer-token validation against the realm's
  JWKS (signature, issuer, audience, expiry). No per-request network round-trip to Keycloak.
- `pyobs_auth.authentication.KeycloakAuthentication` - a DRF `BaseAuthentication` class wiring
  the above into `REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES']`.
- `pyobs_auth.views`/`pyobs_auth.urls` - the browser-facing login redirect + callback views for
  the PKCE flow (session-based), plus a `LogoutView` that also ends the Keycloak SSO session via
  RP-Initiated Logout - but only for sessions that came from Keycloak in the first place. A plain
  local-password session just gets an ordinary local logout, so one "Log out" link/URL works
  correctly either way without the caller needing to know how the user signed in.

## Configuration

Add to `INSTALLED_APPS` and configure via the `PYOBS_AUTH` setting:

```python
INSTALLED_APPS = [
    ...,
    "pyobs_auth",
]

PYOBS_AUTH = {
    "SERVER_URL": "https://keycloak.example.org",
    "REALM": "pyobs",
    "CLIENT_ID": "archive",
    "CLIENT_SECRET": os.getenv("KEYCLOAK_CLIENT_SECRET"),
    "REDIRECT_URI": "https://archive.example.org/accounts/keycloak/callback/",
    # optional - only needed to use LogoutView's Keycloak SSO logout. Must be registered as a
    # "Valid post logout redirect URI" for this client in Keycloak.
    "POST_LOGOUT_REDIRECT_URI": "https://archive.example.org/",
    # dotted path to a callable(claims: dict) -> django.contrib.auth.models.User (or None)
    "USER_RESOLVER": "myapp.authentication.resolve_user",
}

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "pyobs_auth.authentication.KeycloakAuthentication",
        # ... any other authentication classes that must keep working, e.g. an existing
        # DRF TokenAuthentication for service-to-service calls - additive, not a replacement.
    ],
}
```

```python
# urls.py
urlpatterns = [
    path("accounts/keycloak/", include("pyobs_auth.urls")),
    ...
]
```

Point your existing "Log out" link/form at `pyobs_auth:logout` instead of Django's built-in
`logout` view - it's POST-only (matching Django's own CSRF-safe logout convention) and handles
both kinds of session correctly:

```html
<form method="post" action="{% url 'pyobs_auth:logout' %}">{% csrf_token %}
    <button type="submit">Log out</button>
</form>
```

### `USER_RESOLVER`

pyobs-auth deliberately doesn't decide how a validated token maps to your app's local `User`
model - each service's schema is different (e.g. `pyobs-archive`'s existing `Profile` model vs.
`pyobs-robotic-backend`, which has none yet). Provide a callable that takes the validated JWT
claims and returns a `User` (or `None` to reject):

```python
from django.contrib.auth.models import User


def resolve_user(claims: dict) -> User | None:
    # Keycloak's `sub` claim is the join key - stable across username/email changes,
    # and the same whether the user authenticated locally or via a brokered upstream IdP.
    user, _ = User.objects.get_or_create(
        keycloak_sub=claims["sub"],
        defaults={"username": claims.get("preferred_username", claims["sub"])},
    )
    return user
```

## Development

```bash
uv sync --group dev
uv run pytest
uv run ruff check pyobs_auth/
uv run black --check .
uv run pyrefly check pyobs_auth
```
