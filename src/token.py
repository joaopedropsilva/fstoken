from pickle import dumps, loads
from base64 import b64encode, b64decode

from .nacl import NaclBinder


class Token:
    """
    Implements methods to build a token in the form of:
    <public_key>.<payload>.<signature>

    All token parts are encoded in Base64 by default.
    """

    @staticmethod
    def _encode_b64_utf8(data: bytes) -> str:
        return b64encode(data).decode("utf-8")

    @staticmethod
    def _to_bytes(data: dict) -> bytes:
        # Check pickle safety
        return dumps(data)

    @staticmethod
    def _to_dict(data: bytes) -> dict:
        return loads(data)

    @classmethod
    def encode(cls, seed: bytes, payload: dict) -> str:
        processed_payload = cls._to_bytes(payload)
        (public_key, message, sig) = NaclBinder.sign_message(seed,
                                                             processed_payload)

        public_key = cls._encode_b64_utf8(public_key)
        payload = cls._encode_b64_utf8(message)
        signature = cls._encode_b64_utf8(sig)

        return f"{public_key}.{payload}.{signature}"

    @classmethod
    def decode(cls, token: str):
        parts = token.split(".")
        if len(parts) != 3:
            return ""

        public_key = b64decode(parts[0])
        payload = b64decode(parts[1])
        signature = b64decode(parts[2])

        is_ok = NaclBinder.verify_message(public_key, payload, signature)
        processed_payload = "" if not is_ok else cls._to_dict(payload)

        return public_key, processed_payload, signature

