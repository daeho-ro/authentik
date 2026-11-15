"""Client for the Yubico OTP validation protocol, version 2.0"""

from base64 import b64decode, b64encode
from hashlib import sha1
from hmac import compare_digest
from hmac import new as hmac_new
from secrets import token_hex

from requests import RequestException
from structlog.stdlib import get_logger

from authentik.lib.utils.http import get_http_session

LOGGER = get_logger()

YUBICLOUD_API_URL = "https://api.yubico.com/wsapi/2.0/verify"

MODHEX = frozenset("cbdefghijklnrtuv")
# The encrypted part of an OTP is always 32 characters, the public ID before it 2 to 16.
OTP_SECRET_LENGTH = 32
OTP_MIN_LENGTH = OTP_SECRET_LENGTH + 2
OTP_MAX_LENGTH = OTP_SECRET_LENGTH + 16

STATUS_OK = "OK"
# Not sent by the server; used when no valid response was received.
STATUS_CLIENT_ERROR = "CLIENT_ERROR"


def normalize_otp(otp: str) -> str:
    """Strip whitespace and lowercase an OTP as typed by the key"""
    return otp.strip().lower()


def is_valid_otp(otp: str) -> bool:
    """Check whether a normalized OTP has a valid length and only modhex characters"""
    return OTP_MIN_LENGTH <= len(otp) <= OTP_MAX_LENGTH and set(otp) <= MODHEX


def public_id(otp: str) -> str:
    """The public ID of the key that generated a valid OTP"""
    return otp[:-OTP_SECRET_LENGTH]


def sign(params: dict[str, str], key: bytes) -> str:
    """Signature over all parameters except `h`, sorted by name"""
    message = "&".join(f"{name}={params[name]}" for name in sorted(params) if name != "h")
    return b64encode(hmac_new(key, message.encode(), sha1).digest()).decode()


class YubicoOTPClient:
    """Verifies OTPs against a validation server, such as YubiCloud"""

    def __init__(self, api_url: str, client_id: str, secret_key: str):
        self.api_url = api_url
        self.client_id = client_id
        self.key = b64decode(secret_key)

    def verify(self, otp: str) -> str:
        """Verify an OTP and return the status from the server, `OK` when it is valid"""
        nonce = token_hex(16)
        params = {"id": self.client_id, "otp": otp, "nonce": nonce}
        params["h"] = sign(params, self.key)
        try:
            response = get_http_session().get(self.api_url, params=params)
            response.raise_for_status()
        except RequestException as exc:
            LOGGER.warning("Failed to reach Yubico OTP validation server", exc=exc)
            return STATUS_CLIENT_ERROR
        values = dict(line.split("=", 1) for line in response.text.splitlines() if "=" in line)
        if not compare_digest(values.get("h", ""), sign(values, self.key)):
            LOGGER.warning("Invalid signature from Yubico OTP validation server")
            return STATUS_CLIENT_ERROR
        if values.get("otp") != otp or values.get("nonce") != nonce:
            LOGGER.warning("Yubico OTP validation server answered a different request")
            return STATUS_CLIENT_ERROR
        return values.get("status", STATUS_CLIENT_ERROR)
