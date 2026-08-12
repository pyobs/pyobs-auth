from django.urls import include, path

urlpatterns = [
    path("accounts/keycloak/", include("pyobs_auth.urls")),
]
