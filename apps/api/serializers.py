from django.contrib.auth import get_user_model
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _

from rest_framework import serializers, status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

User = get_user_model()


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["username"] = user.username

        return token

    def validate(self, attrs):
        data = super().validate(attrs)

        refresh = self.get_token(self.user)

        data["refresh"] = str(refresh)
        data["access"] = str(refresh.access_token)
        data["is_admin"] = self.user.is_superuser
        data["email"] = self.user.email
        data["username"] = self.user.email

        if api_settings.UPDATE_LAST_LOGIN:
            api_settings(None, self.user)

        return data


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration
    """

    username = serializers.CharField(max_length=150, required=True)
    password = serializers.CharField(
        max_length=150, write_only=True, required=True, style={"input_type": "password"}
    )

    class Meta:
        model = User
        fields = ["username", "email", "password"]

    def validate(self, attrs):
        username = attrs.get("username")
        user = User.objects.filter(username=username).exists()

        if user:
            raise serializers.ValidationError(
                _(f"User with username {username} already exists."),
                code=status.HTTP_400_BAD_REQUEST,
            )

        return super().validate(attrs)

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class EmailVerificationSerializer(serializers.ModelSerializer):
    tokens = serializers.CharField()

    class Meta:
        model = User
        fields = ("tokens",)


class RequestPasswordForgetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    class Meta:
        fields = ("email",)


class SetNewPasswordSerializer(serializers.Serializer):
    password = serializers.CharField(min_length=6, max_length=68, write_only=True)
    token = serializers.CharField(min_length=6, write_only=True)
    uidb_64 = serializers.CharField(min_length=1, write_only=True)

    class Meta:
        fields = (
            "password",
            "token",
            "uidb_64",
        )

        def validate(self, attrs):
            try:
                password = attrs.get("password")
                token = attrs.get("token")
                uidb_64 = attrs.get("uidb_64")

                id = force_str(urlsafe_base64_decode(uidb_64))
                user = User.objects.get(id=id)

                if not PasswordResetTokenGenerator().check_token(
                    user=user, token=token
                ):
                    raise AuthenticationFailed(_("The reset link is invalid"), 401)

                user.set_password(password)
                user.save()

                return user

            except Exception as e:
                raise AuthenticationFailed(_("The reset link is invalid"), 401)
