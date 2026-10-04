# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries for releases before this file existed were generated from commit subjects.

## [2.1.0] - 2026-08-31

- Add API/architecture docs and retrospective plan for the authorize() gate (#15)
- Recommend ENFORCE_LOCAL_ACTIVE=True in example config and docs, preserving pre-2.1 activation behavior by default
- Lower non-invalid_grant refresh-failure log to debug; avoids warning-per-request flood during a Keycloak outage
- Address review: signed-cookie sessions, refresh-failure handling, auth ordering, config parsing
- Centralize authorization via Keycloak groups/roles

## [2.0.0] - 2026-08-26

- Remove cross-repo specs/ link from Sphinx docs
- Add Dependabot auto-merge workflow for patch/minor updates
- Add .readthedocs.yml
- Add Sphinx docs from scratch
- Update pyobs-robotic-backend references to pyobs-portal
- Add IDP_HINT support for one-click IdP login
- Render a styled error page instead of bare-text 400s
- Refuse login/authentication for inactive resolved users
- Allow Django 6, not just 5.2, in the dependency pin
- Add Keycloak SSO logout (RP-Initiated Logout)
- Fix redirect to blank Location when next param is present but empty
- KeycloakAuthentication: defer instead of raising for tokens from another issuer
- Add GitHub Actions workflow to publish to PyPI on version tags
- to version 2.0.0.dev0
- Initial implementation: Keycloak/OIDC client, JWKS validation, DRF authentication
