"""Yubico OTP Authenticator models"""

from typing import TYPE_CHECKING, Any

from django.db import models
from django.utils.translation import gettext_lazy as _
from rest_framework.serializers import BaseSerializer

from authentik.core.types import UserSettingSerializer
from authentik.flows.models import ConfigurableStage, FriendlyNamedStage, Stage
from authentik.lib.models import SerializerModel
from authentik.stages.authenticator.models import Device, ThrottlingMixin
from authentik.stages.authenticator_yubico_otp.client import (
    STATUS_OK,
    YUBICLOUD_API_URL,
    YubicoOTPClient,
    is_valid_otp,
    normalize_otp,
    public_id,
)

if TYPE_CHECKING:
    from authentik.flows.stage import StageView


class AuthenticatorYubicoOTPStage(ConfigurableStage, FriendlyNamedStage, Stage):
    """Setup Yubico OTP authentication for the user."""

    api_url = models.TextField(
        default=YUBICLOUD_API_URL,
        help_text=_("Validation server that verifies OTPs, YubiCloud by default."),
    )
    client_id = models.TextField(help_text=_("Client ID for the validation server."))
    secret_key = models.TextField(help_text=_("Secret key for the validation server."))

    @property
    def serializer(self) -> type[BaseSerializer[Any]]:
        from authentik.stages.authenticator_yubico_otp.api import (
            AuthenticatorYubicoOTPStageSerializer,
        )

        return AuthenticatorYubicoOTPStageSerializer

    @property
    def view(self) -> type[StageView]:
        from authentik.stages.authenticator_yubico_otp.stage import (
            AuthenticatorYubicoOTPStageView,
        )

        return AuthenticatorYubicoOTPStageView

    @property
    def component(self) -> str:
        return "ak-stage-authenticator-yubico-otp-form"

    def ui_user_settings(self) -> UserSettingSerializer | None:
        return UserSettingSerializer(
            data={
                "title": self.friendly_name or str(self._meta.verbose_name),
                "component": "ak-user-settings-authenticator-yubico-otp",
            }
        )

    def client(self) -> YubicoOTPClient:
        """Client for this stage's validation server"""
        return YubicoOTPClient(self.api_url, self.client_id, self.secret_key)

    def __str__(self) -> str:
        return f"Yubico OTP Authenticator Setup Stage {self.name}"

    class Meta:
        verbose_name = _("Yubico OTP Authenticator Setup Stage")
        verbose_name_plural = _("Yubico OTP Authenticator Setup Stages")


class YubicoOTPDevice(SerializerModel, ThrottlingMixin, Device):
    """A YubiKey slot that generates Yubico OTPs, identified by its public ID"""

    stage = models.ForeignKey(AuthenticatorYubicoOTPStage, on_delete=models.PROTECT)
    public_id = models.CharField(max_length=16)

    @property
    def serializer(self) -> type[BaseSerializer[Any]]:
        from authentik.stages.authenticator_yubico_otp.api import YubicoOTPDeviceSerializer

        return YubicoOTPDeviceSerializer

    def verify_token(self, token: str) -> bool:
        otp = normalize_otp(token)
        # An OTP from another key is not a failed attempt for this one
        if not is_valid_otp(otp) or public_id(otp) != self.public_id:
            return False
        verify_allowed, _ = self.verify_is_allowed()  # type: ignore[no-untyped-call]
        if not verify_allowed:
            return False
        if self.stage.client().verify(otp) == STATUS_OK:
            self.throttle_reset()  # type: ignore[no-untyped-call]
            return True
        self.throttle_increment()  # type: ignore[no-untyped-call]
        return False

    def __str__(self) -> str:
        if not self.pk:
            return "New Yubico OTP Device"
        return f"Yubico OTP Device {self.public_id} for {self.user_id}"

    class Meta(Device.Meta):
        verbose_name = _("Yubico OTP Device")
        verbose_name_plural = _("Yubico OTP Devices")
        unique_together = (("user", "public_id"),)
