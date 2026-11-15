"""Yubico OTP"""

from authentik.blueprints.apps import ManagedAppConfig


class AuthentikStageAuthenticatorYubicoOTPConfig(ManagedAppConfig):
    """Yubico OTP App config"""

    name = "authentik.stages.authenticator_yubico_otp"
    label = "authentik_stages_authenticator_yubico_otp"
    verbose_name = "authentik Stages.Authenticator.Yubico OTP"
    default = True
