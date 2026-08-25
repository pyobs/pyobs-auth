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

See :doc:`api` for using ``KeycloakClient``/``TokenValidator`` directly outside the Django
integration (e.g. service-to-service calls).
