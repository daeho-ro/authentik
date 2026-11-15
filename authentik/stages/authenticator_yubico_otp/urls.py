"""API URLs"""

from authentik.stages.authenticator_yubico_otp.api import (
    AuthenticatorYubicoOTPStageViewSet,
    YubicoOTPAdminDeviceViewSet,
    YubicoOTPDeviceViewSet,
)

api_urlpatterns = [
    ("authenticators/yubico_otp", YubicoOTPDeviceViewSet),
    ("authenticators/admin/yubico_otp", YubicoOTPAdminDeviceViewSet, "admin-yubicootpdevice"),
    ("stages/authenticator/yubico_otp", AuthenticatorYubicoOTPStageViewSet),
]
