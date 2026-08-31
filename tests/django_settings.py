SECRET_KEY = "test"
USE_TZ = True

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "pyobs_auth",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "APP_DIRS": True,
    },
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "pyobs_auth.middleware.KeycloakSessionRefreshMiddleware",
]

ROOT_URLCONF = "tests.urls"

PYOBS_AUTH = {
    "SERVER_URL": "https://keycloak.example.org",
    "REALM": "pyobs",
    "CLIENT_ID": "archive",
    "CLIENT_SECRET": "test-secret",
    "REDIRECT_URI": "https://archive.example.org/accounts/keycloak/callback/",
    "USER_RESOLVER": "tests.helpers.resolve_user",
}
