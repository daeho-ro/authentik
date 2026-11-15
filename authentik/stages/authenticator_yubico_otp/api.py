"""AuthenticatorYubicoOTPStage API Views"""

from base64 import b64decode
from binascii import Error as Base64Error
from typing import Any

from django.utils.translation import gettext_lazy as _
from rest_framework import mixins
from rest_framework.serializers import ValidationError
from rest_framework.viewsets import GenericViewSet, ModelViewSet

from authentik.core.api.groups import PartialUserSerializer
from authentik.core.api.used_by import UsedByMixin
from authentik.core.api.utils import ModelSerializer
from authentik.flows.api.stages import StageSerializer
from authentik.stages.authenticator_yubico_otp.models import (
    AuthenticatorYubicoOTPStage,
    YubicoOTPDevice,
)


class AuthenticatorYubicoOTPStageSerializer(StageSerializer):
    """AuthenticatorYubicoOTPStage Serializer"""

    def validate_secret_key(self, secret_key: str) -> str:
        """The secret key must be base64, as issued by the validation server"""
        try:
            b64decode(secret_key, validate=True)
        except Base64Error as exc:
            raise ValidationError(_("The secret key must be base64 encoded.")) from exc
        return secret_key

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        # The key is write-only, so updates may leave it out to keep the current one
        if not self.instance and not attrs.get("secret_key"):
            raise ValidationError({"secret_key": _("This field is required.")})
        validated: dict[str, Any] = super().validate(attrs)
        return validated

    class Meta:
        model = AuthenticatorYubicoOTPStage
        fields = StageSerializer.Meta.fields + [
            "configure_flow",
            "friendly_name",
            "api_url",
            "client_id",
            "secret_key",
        ]
        extra_kwargs = {
            "secret_key": {"write_only": True, "required": False},
        }


class AuthenticatorYubicoOTPStageViewSet(UsedByMixin, ModelViewSet[AuthenticatorYubicoOTPStage]):
    """AuthenticatorYubicoOTPStage Viewset"""

    queryset = AuthenticatorYubicoOTPStage.objects.all()
    serializer_class = AuthenticatorYubicoOTPStageSerializer
    filterset_fields = "__all__"
    ordering = ["name"]
    search_fields = ["name"]


class YubicoOTPDeviceSerializer(ModelSerializer):
    """Serializer for Yubico OTP authenticator devices"""

    user = PartialUserSerializer(read_only=True)

    class Meta:
        model = YubicoOTPDevice
        fields = ["name", "pk", "public_id", "user"]
        depth = 2
        extra_kwargs = {
            "public_id": {"read_only": True},
        }


class YubicoOTPDeviceViewSet(
    mixins.RetrieveModelMixin,
    mixins.UpdateModelMixin,
    mixins.DestroyModelMixin,
    UsedByMixin,
    mixins.ListModelMixin,
    GenericViewSet[YubicoOTPDevice],
):
    """Viewset for Yubico OTP authenticator devices"""

    queryset = YubicoOTPDevice.objects.all()
    serializer_class = YubicoOTPDeviceSerializer
    search_fields = ["name"]
    filterset_fields = ["name"]
    ordering = ["name"]
    owner_field = "user"


class YubicoOTPAdminDeviceViewSet(ModelViewSet[YubicoOTPDevice]):
    """Viewset for Yubico OTP authenticator devices (for admins)"""

    queryset = YubicoOTPDevice.objects.all()
    serializer_class = YubicoOTPDeviceSerializer
    search_fields = ["name"]
    filterset_fields = ["name"]
    ordering = ["name"]
