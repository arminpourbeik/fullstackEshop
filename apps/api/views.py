import jwt
from decouple import config

from django.contrib.auth import get_user_model
from django.urls import reverse
from django.contrib.sites.shortcuts import get_current_site
from django.utils.translation import gettext_lazy as _
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import (
    smart_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
)
from django.contrib.auth.tokens import PasswordResetTokenGenerator

from rest_framework import views
from rest_framework import generics
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework import status
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

from utils.send_email import Util

from . import serializers


User = get_user_model()


class MyTokenObtainPairView(TokenObtainPairView):
    serializer_class = serializers.MyTokenObtainPairSerializer


class RegistrationView(generics.GenericAPIView):
    serializer_class = serializers.RegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=True):
            serializer.save()

            user_data = serializer.data
            User = get_user_model()
            user = User.objects.get(username=user_data["username"])
            token = RefreshToken.for_user(user=user).access_token
            current_site = get_current_site(request=request).domain
            relative_link = reverse("email-verify")
            abs_url = (
                f"{request.scheme}://{current_site}{relative_link}?token={str(token)}"
            )

            email_body = _(
                f"Hello {user.username}, use the link below to verify your email \n {abs_url}"
            )

            data = {
                "email_body": email_body,
                "to_email": user.email,
                "email_subject": "Verify your email",
            }

            Util.send_email(data=data)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(views.APIView):
    """
    View for confirm email with token
    """

    serializer_class = serializers.EmailVerificationSerializer

    token_param_config = openapi.Parameter(
        name="token",
        in_=openapi.IN_QUERY,
        description="User Token",
        type=openapi.TYPE_STRING,
    )

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request):
        token = request.GET.get("token")
        try:
            payload = jwt.decode(token, config("SECRET_KEY"), algorithms=["HS256"])
            user = get_user_model().objects.get(id=payload["user_id"])
            if not user.email_verified:
                user.email_verified = True
                user.save()

                return Response(
                    {"msg": _("Successfully activated.")},
                    status=status.HTTP_200_OK,
                )
        except jwt.ExpiredSignatureError:
            return Response(
                {"error": _("Activation link expired.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except jwt.DecodeError:
            return Response(
                {"error": _("Invalid token")},
                status=status.HTTP_400_BAD_REQUEST,
            )


class RequestNewPasswordView(generics.GenericAPIView):
    """
    View for request new password
    """

    serializer_class = serializers.RequestPasswordForgetSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)

        email = serializer.data["email"]

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)

            # We want to sent user_id but encoded
            uid64 = urlsafe_base64_encode(smart_bytes(user.id))
            token = PasswordResetTokenGenerator().make_token(user=user)

            current_site = get_current_site(request=request).domain
            relative_link = reverse(
                "password-reset-confirm",
                kwargs={
                    "uidb64": uid64,
                    "token": token,
                },
            )
            abs_url = f"{request.scheme}://{current_site}{relative_link}"
            email_body = _(
                f"Hi, use the link below to reset your password \n {abs_url}"
            )
            data = {
                "email_body": email_body,
                "to_email": user.email,
                "email_subject": _(
                    "Reset your password",
                ),
            }

            Util.send_email(data=data)

            return Response(
                {"success": _("We have sent you a link to reset your password")},
                status=status.HTTP_200_OK,
            )


class PasswordTokenCheckApi(generics.GenericAPIView):
    """
    Check user token for password change request view
    """

    def get(self, request, uidb64, token):
        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)

            if not PasswordResetTokenGenerator().check_token(user=user, token=token):
                return Response(
                    {"error": "Token is not valid, please request a new one."},
                    status=status.status.HTTP_401_UNAUTHORIZED,
                )

            return Response(
                {
                    "success": True,
                    "message": _("Credentials is valid"),
                    "uidb64": uidb64,
                    "token": token,
                },
                status=status.HTTP_200_OK,
            )

        except DjangoUnicodeDecodeError:
            return Response(
                {"error": _("Token is not valid, please request a new one.")},
                status=status.status.HTTP_401_UNAUTHORIZED,
            )


class SetNewPasswordApiView(generics.GenericAPIView):
    """
    Set new password view
    """

    serializer_class = serializers.SetNewPasswordSerializer

    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        serializer.is_valid(raise_exception=True)

        return Response(
            {"success": True, "message": _("Password reset successfully.")},
            status=status.HTTP_200_OK,
        )
