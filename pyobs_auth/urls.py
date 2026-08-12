from django.urls import path

from .views import CallbackView, LoginView, LogoutView

app_name = "pyobs_auth"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("callback/", CallbackView.as_view(), name="callback"),
    path("logout/", LogoutView.as_view(), name="logout"),
]
