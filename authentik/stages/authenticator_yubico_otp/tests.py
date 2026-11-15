"""Yubico OTP authenticator tests"""

from base64 import b64encode
from secrets import token_bytes
from typing import Any
from urllib.parse import parse_qs, urlparse

from django.urls import reverse
from requests_mock import Mocker

from authentik.admin.utils import get_system_settings
from authentik.core.tests.utils import create_test_admin_user, create_test_flow
from authentik.flows.models import FlowStageBinding
from authentik.flows.tests import APIFlowTestCase
from authentik.lib.generators import generate_id
from authentik.stages.authenticator_validate.models import AuthenticatorValidateStage, DeviceClasses
from authentik.stages.authenticator_yubico_otp.client import (
    STATUS_CLIENT_ERROR,
    STATUS_OK,
    YUBICLOUD_API_URL,
    is_valid_otp,
    public_id,
    sign,
)
from authentik.stages.authenticator_yubico_otp.models import (
    AuthenticatorYubicoOTPStage,
    YubicoOTPDevice,
)
from authentik.stages.identification.models import IdentificationStage, UserFields

KEY_ID = "cccccccbtrnk"
OTP = KEY_ID + "jdluhlhkvdthhiblrvgvddicghnbgnct"
OTHER_KEY_OTP = "ccccccdkgrvd" + "jdluhlhkvdthhiblrvgvddicghnbgnct"


class ValidationServer:
    """Answers verify requests like YubiCloud, signed with the given key"""

    def __init__(self, key: bytes, status: str = STATUS_OK) -> None:
        self.key = key
        self.status = status
        self.requests: list[dict[str, str]] = []

    def __call__(self, request: Any, context: Any) -> str:
        query = {name: values[0] for name, values in parse_qs(urlparse(request.url).query).items()}
        self.requests.append(query)
        response = {
            "otp": query["otp"],
            "nonce": query["nonce"],
            "t": "2026-11-15T00:00:00Z0000",
            "status": self.status,
        }
        response["h"] = sign(response, self.key)
        return "\r\n".join(f"{name}={value}" for name, value in response.items()) + "\r\n"


class YubicoOTPTestCase(APIFlowTestCase):
    """Common setup: a setup stage with a validation server key"""

    def setUp(self) -> None:
        super().setUp()
        # Avatars would be looked up over HTTP, which the validation server mock intercepts
        settings = get_system_settings()
        settings.avatars = "none"
        settings.save()  # type: ignore[no-untyped-call]
        self.key = token_bytes(20)
        self.user = create_test_admin_user()
        self.stage = AuthenticatorYubicoOTPStage.objects.create(
            name=generate_id(),
            client_id="12345",
            secret_key=b64encode(self.key).decode(),
        )

    def server(self, mocker: Mocker, status: str = STATUS_OK) -> ValidationServer:
        server = ValidationServer(self.key, status)
        mocker.get(YUBICLOUD_API_URL, text=server)
        return server


class TestYubicoOTPClient(YubicoOTPTestCase):
    """Validation protocol client"""

    def test_otp_format(self) -> None:
        """OTPs are modhex with a public ID in front of 32 characters"""
        self.assertTrue(is_valid_otp(OTP))
        self.assertEqual(public_id(OTP), KEY_ID)
        self.assertFalse(is_valid_otp("123456"))
        self.assertFalse(is_valid_otp(OTP.replace("c", "a")))
        self.assertFalse(is_valid_otp(OTP[-32:]))

    @Mocker()
    def test_verify_ok(self, mocker: Mocker) -> None:
        """A signed OK answer verifies, and the request is signed too"""
        server = self.server(mocker)
        self.assertEqual(self.stage.client().verify(OTP), STATUS_OK)
        request = server.requests[0]
        self.assertEqual(request["id"], "12345")
        self.assertEqual(request["otp"], OTP)
        self.assertEqual(request["h"], sign(request, self.key))

    @Mocker()
    def test_verify_status(self, mocker: Mocker) -> None:
        """Statuses other than OK are passed on"""
        self.server(mocker, "REPLAYED_OTP")
        self.assertEqual(self.stage.client().verify(OTP), "REPLAYED_OTP")

    @Mocker()
    def test_verify_bad_signature(self, mocker: Mocker) -> None:
        """An answer signed with another key is rejected"""
        server = ValidationServer(token_bytes(20))
        mocker.get(YUBICLOUD_API_URL, text=server)
        self.assertEqual(self.stage.client().verify(OTP), STATUS_CLIENT_ERROR)

    @Mocker()
    def test_verify_other_otp(self, mocker: Mocker) -> None:
        """An answer for another OTP is rejected, even when signed"""
        response = {"otp": OTHER_KEY_OTP, "nonce": "x" * 32, "status": STATUS_OK}
        response["h"] = sign(response, self.key)
        mocker.get(YUBICLOUD_API_URL, text="\r\n".join(f"{k}={v}" for k, v in response.items()))
        self.assertEqual(self.stage.client().verify(OTP), STATUS_CLIENT_ERROR)

    @Mocker()
    def test_verify_server_error(self, mocker: Mocker) -> None:
        """HTTP errors count as a failed verification"""
        mocker.get(YUBICLOUD_API_URL, status_code=500)
        self.assertEqual(self.stage.client().verify(OTP), STATUS_CLIENT_ERROR)


class TestYubicoOTPDevice(YubicoOTPTestCase):
    """Device verification"""

    def setUp(self) -> None:
        super().setUp()
        self.device = YubicoOTPDevice.objects.create(
            user=self.user, stage=self.stage, public_id=KEY_ID, name=generate_id()
        )

    @Mocker()
    def test_verify_token(self, mocker: Mocker) -> None:
        """An OTP from this key is checked with the validation server"""
        self.server(mocker)
        self.assertTrue(self.device.verify_token(OTP.upper() + "\n"))

    @Mocker()
    def test_verify_token_other_key(self, mocker: Mocker) -> None:
        """An OTP from another key fails without asking the server or counting a failure"""
        server = self.server(mocker)
        self.assertFalse(self.device.verify_token(OTHER_KEY_OTP))
        self.assertEqual(server.requests, [])
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 0)

    @Mocker()
    def test_verify_token_rejected(self, mocker: Mocker) -> None:
        """A rejected OTP counts as a failed attempt"""
        self.server(mocker, "REPLAYED_OTP")
        self.assertFalse(self.device.verify_token(OTP))
        self.device.refresh_from_db()
        self.assertEqual(self.device.throttling_failure_count, 1)


class TestYubicoOTPSetupStage(YubicoOTPTestCase):
    """Setup stage"""

    def setUp(self) -> None:
        super().setUp()
        self.flow = create_test_flow()
        FlowStageBinding.objects.create(target=self.flow, stage=self.stage, order=0)
        self.client.force_login(self.user)
        self.url = reverse("authentik_api:flow-executor", kwargs={"flow_slug": self.flow.slug})

    def test_challenge(self) -> None:
        """The stage asks for an OTP"""
        response = self.client.get(self.url)
        self.assertStageResponse(
            response, self.flow, self.user, component="ak-stage-authenticator-yubico-otp"
        )

    @Mocker()
    def test_setup(self, mocker: Mocker) -> None:
        """A verified OTP registers its key"""
        self.server(mocker)
        self.client.get(self.url)
        response = self.client.post(self.url, {"code": OTP})
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))
        device = YubicoOTPDevice.objects.get(user=self.user)
        self.assertEqual(device.public_id, KEY_ID)
        self.assertEqual(device.stage, self.stage)

    @Mocker()
    def test_setup_invalid(self, mocker: Mocker) -> None:
        """OTPs that are malformed, rejected or from a registered key don't register"""
        self.server(mocker, "BAD_OTP")
        self.client.get(self.url)
        for code in ["123456", OTP]:
            response = self.client.post(self.url, {"code": code})
            self.assertStageResponse(
                response,
                self.flow,
                component="ak-stage-authenticator-yubico-otp",
                response_errors={"code": response.json()["response_errors"]["code"]},
            )
        YubicoOTPDevice.objects.create(
            user=self.user, stage=self.stage, public_id=KEY_ID, name=generate_id()
        )
        response = self.client.post(self.url, {"code": OTP})
        self.assertEqual(
            response.json()["response_errors"]["code"][0]["string"],
            "This YubiKey is already registered.",
        )
        self.assertEqual(YubicoOTPDevice.objects.filter(user=self.user).count(), 1)


class TestYubicoOTPValidation(YubicoOTPTestCase):
    """Authenticator validation stage with Yubico OTP devices"""

    @Mocker()
    def test_validate(self, mocker: Mocker) -> None:
        """An OTP from a registered key passes the validation stage"""
        server = self.server(mocker)
        YubicoOTPDevice.objects.create(
            user=self.user, stage=self.stage, public_id=KEY_ID, name=generate_id()
        )
        flow = create_test_flow()
        ident_stage = IdentificationStage.objects.create(
            name=generate_id(), user_fields=[UserFields.USERNAME]
        )
        validate_stage = AuthenticatorValidateStage.objects.create(
            name=generate_id(), device_classes=[DeviceClasses.YUBICOOTP]
        )
        FlowStageBinding.objects.create(target=flow, stage=ident_stage, order=0)
        FlowStageBinding.objects.create(target=flow, stage=validate_stage, order=1)
        url = reverse("authentik_api:flow-executor", kwargs={"flow_slug": flow.slug})

        self.client.post(url, {"uid_field": self.user.username})
        response = self.client.get(url)
        challenges = response.json()["device_challenges"]
        self.assertEqual([c["device_class"] for c in challenges], [DeviceClasses.YUBICOOTP])

        response = self.client.post(url, {"code": OTHER_KEY_OTP})
        self.assertIn("code", response.json()["response_errors"])
        self.assertEqual(server.requests, [])

        response = self.client.post(url, {"code": OTP})
        self.assertStageRedirects(response, reverse("authentik_core:root-redirect"))


class TestYubicoOTPStageAPI(YubicoOTPTestCase):
    """Stage API"""

    def setUp(self) -> None:
        super().setUp()
        self.client.force_login(self.user)

    def test_create_requires_secret_key(self) -> None:
        """A new stage needs a base64 secret key"""
        url = reverse("authentik_api:authenticatoryubicootpstage-list")
        data = {"name": generate_id(), "client_id": "1"}
        response = self.client.post(url, data)
        self.assertEqual(response.status_code, 400)
        self.assertIn("secret_key", response.json())
        response = self.client.post(url, {**data, "secret_key": "not base64!"})
        self.assertEqual(response.status_code, 400)
        response = self.client.post(url, {**data, "secret_key": b64encode(b"key").decode()})
        self.assertEqual(response.status_code, 201)
        self.assertNotIn("secret_key", response.json())

    def test_update_keeps_secret_key(self) -> None:
        """Updating without a secret key keeps the current one"""
        url = reverse(
            "authentik_api:authenticatoryubicootpstage-detail",
            kwargs={"pk": self.stage.pk},
        )
        response = self.client.put(url, {"name": self.stage.name, "client_id": "67890"})
        self.assertEqual(response.status_code, 200)
        self.stage.refresh_from_db()
        self.assertEqual(self.stage.client_id, "67890")
        self.assertEqual(self.stage.secret_key, b64encode(self.key).decode())
