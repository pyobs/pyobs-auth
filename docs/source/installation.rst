Installation
############

Add to your Django project::

    uv add pyobs-auth

Add to ``INSTALLED_APPS`` and wire the login/callback/logout views into your URLconf::

    INSTALLED_APPS = [
        ...,
        "pyobs_auth",
    ]

    # urls.py
    urlpatterns = [
        path("accounts/keycloak/", include("pyobs_auth.urls")),
        ...
    ]

Then configure the ``PYOBS_AUTH`` setting (see :doc:`configuration`) and point your existing
"Log out" link/form at ``pyobs_auth:logout`` instead of Django's built-in ``logout`` view — it's
POST-only (matching Django's own CSRF-safe logout convention) and handles both a Keycloak-backed
session and a plain local-password session correctly, without the caller needing to know which
kind it is::

    <form method="post" action="{% url 'pyobs_auth:logout' %}">{% csrf_token %}
        <button type="submit">Log out</button>
    </form>

If using the browser login flow, also add ``KeycloakSessionRefreshMiddleware`` to
``MIDDLEWARE``, after Django's session and auth middleware (it needs both ``request.session`` and
``django.contrib.auth.logout()``)::

    MIDDLEWARE = [
        ...,
        "django.contrib.sessions.middleware.SessionMiddleware",
        "django.contrib.auth.middleware.AuthenticationMiddleware",
        "pyobs_auth.middleware.KeycloakSessionRefreshMiddleware",
        ...,
    ]

This is what bounds revocation (a group/role change in Keycloak) to roughly one access-token
lifetime instead of ``SESSION_COOKIE_AGE`` — see :ref:`authorization` in :doc:`configuration`.
It's a
no-op for any session that didn't come through the browser login flow (e.g. local-password
Django-admin sessions), so it's safe to add even before configuring
``REQUIRED_GROUPS``/``REQUIRED_ROLES``.

See :doc:`api` for using ``KeycloakClient``/``TokenValidator`` directly outside the Django
integration (e.g. service-to-service calls).
