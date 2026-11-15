"""Yubico OTP Setup stage"""

from typing import Any, cast

from django.http import HttpRequest, HttpResponse
from django.utils.translation import gettext_lazy as _
from rest_framework.fields import CharField
from rest_framework.serializers import ValidationError

from authentik.flows.challenge import Challenge, ChallengeResponse, WithUserInfoChallenge
from authentik.flows.stage import ChallengeStageView
from authentik.stages.authenticator_yubico_otp.client import (
    STATUS_CLIENT_ERROR,
    STATUS_OK,
    is_valid_otp,
    normalize_otp,
    public_id,
)
from authentik.stages.authenticator_yubico_otp.models import (
    AuthenticatorYubicoOTPStage,
    YubicoOTPDevice,
)


class AuthenticatorYubicoOTPChallenge(WithUserInfoChallenge):
    """Yubico OTP Setup challenge"""

    component = CharField(default="ak-stage-authenticator-yubico-otp")


class AuthenticatorYubicoOTPChallengeResponse(ChallengeResponse):
    """Yubico OTP setup response, with an OTP from the key being registered"""

    stage: AuthenticatorYubicoOTPStageView

    code = CharField()
    component = CharField(default="ak-stage-authenticator-yubico-otp")

    def validate_code(self, code: str) -> str:
        otp = normalize_otp(code)
        if not is_valid_otp(otp):
            raise ValidationError(_("This is not a Yubico OTP. Touch your YubiKey to enter one."))
        user = self.stage.get_pending_user()
        if YubicoOTPDevice.objects.filter(user=user, public_id=public_id(otp)).exists():
            raise ValidationError(_("This YubiKey is already registered."))
        stage = cast(AuthenticatorYubicoOTPStage, self.stage.executor.current_stage)
        status = stage.client().verify(otp)
        if status == STATUS_CLIENT_ERROR:
            raise ValidationError(_("The Yubico OTP could not be verified. Try again later."))
        if status != STATUS_OK:
            self.stage.logger.info("Yubico OTP rejected during setup", status=status)
            raise ValidationError(_("Invalid Yubico OTP. Touch your YubiKey to enter a new one."))
        return otp


class AuthenticatorYubicoOTPStageView(ChallengeStageView):
    """Yubico OTP Setup stage"""

    response_class = AuthenticatorYubicoOTPChallengeResponse

    def get(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        if not self.get_pending_user().is_authenticated:
            self.logger.debug("No pending user, continuing")
            return self.executor.stage_ok()
        return super().get(request, *args, **kwargs)

    def get_challenge(self, *args: Any, **kwargs: Any) -> Challenge:
        return AuthenticatorYubicoOTPChallenge(data={})

    def challenge_valid(self, response: ChallengeResponse) -> HttpResponse:
        otp: str = response.validated_data["code"]
        key_id = public_id(otp)
        YubicoOTPDevice.objects.create(
            user=self.get_pending_user(),
            stage=self.executor.current_stage,
            public_id=key_id,
            name=f"YubiKey {key_id}",
            confirmed=True,
        )
        return self.executor.stage_ok()
