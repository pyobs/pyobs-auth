# CLAUDE.md

Entry points for working in this repo.

## What this is

`pyobs-auth` is a shared Keycloak/OIDC authentication client for pyobs web services
(`pyobs-archive`, `pyobs-portal`, and future services), so each one doesn't reimplement OIDC
discovery, token validation, and user mapping on its own. Single issuer only, by design — every
service trusts exactly one Keycloak realm; any upstream identity provider is meant to be brokered
*behind* that Keycloak instance, not validated directly by this library (see
[`docs/source/architecture.rst`](docs/source/architecture.rst)). Full installation, configuration,
and API reference live in [`docs/source/`](docs/source/) (Sphinx —
`cd docs && uv run --group dev make html`).

## Design history and planning

This repo keeps its own implementation plans under `specs/plans/`; see `specs/index.md` for the
current list. Design docs and ADRs that concern `pyobs-auth` (it's a shared dependency, so most
design work here is cross-repo) live in `pyobs-core`'s `specs/` tree instead, tagged with a
`Repos:` line — see `pyobs-core/CLAUDE.md`'s "Cross-repo docs" section for the convention.

## Tooling

- Lint: `uv run ruff check pyobs_auth/`
- Format: `uv run black --check .`
- Type checking: `uv run pyrefly check pyobs_auth`
- Tests: `uv run pytest`
