# pyobs-auth

Shared Keycloak/OIDC authentication client for pyobs web services (`pyobs-archive`,
`pyobs-portal`, and future services), so each one doesn't reimplement OIDC discovery,
token validation, and user mapping on its own.

Single issuer only, by design: every service trusts exactly one Keycloak realm. Any upstream
identity provider (an institute's SSO, a self-hosted `observation-portal`, ...) is meant to be
brokered *behind* that Keycloak instance, not validated directly by this library - see
[`docs/source/architecture.rst`](docs/source/architecture.rst) for the full reasoning.

## Documentation

Full installation (adding this to a Django project), configuration (every `PYOBS_AUTH` key),
architecture, and API reference: see [`docs/source/`](docs/source/) (built with Sphinx —
`cd docs && uv run --group dev make html`).

## Development

```bash
git clone https://github.com/pyobs/pyobs-auth.git
cd pyobs-auth
uv sync --group dev
uv run pytest
uv run ruff check pyobs_auth/
uv run black --check .
uv run pyrefly check pyobs_auth
```
