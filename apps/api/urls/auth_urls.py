from django.urls import path

from rest_framework_simplejwt.views import TokenRefreshView

from apps.api import views

urlpatterns = [
    path(
        "users/login/",
        views.MyTokenObtainPairView.as_view(),
        name="login",
    ),
    path(
        "users/token/refresh/",
        TokenRefreshView.as_view(),
        name="token-refresh",
    ),
    path(
        "users/request-rest-email/",
        views.RequestNewPasswordView.as_view(),
        name="request-rest-email",
    ),
    path(
        "users/register/",
        views.RegistrationView.as_view(),
        name="register",
    ),
    path(
        "users/verify-email/",
        views.VerifyEmailView.as_view(),
        name="email-verify",
    ),
    path(
        "users/password-reset/<uidb64>/<token>/",
        views.PasswordTokenCheckApi.as_view(),
        name="password-reset-confirm",
    ),
    path(
        "users/password-reset-complete/",
        views.SetNewPasswordApiView.as_view(),
        name="password-reset-complete",
    ),
]
