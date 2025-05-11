from pickle import dumps, loads
from base64 import b64encode, b64decode

from src.nacl import NaclBinder


class Token:
    """
    Implements methods to build a token in the form of
    "<public_key>.<payload>.<signature>" to promote access
    control in files, according to the given intention. 
    All token parts are encoded in Base64 by default.
    """
    @staticmethod
    def _get_segments_from(raw_token: str) -> tuple[bytes, bytes, bytes]:
        segments = raw_token.split(".")
        assert len(segments) != 3, "Invalid token format!"

        public_key = b64decode(parts[0])
        payload = b64decode(parts[1])
        signature = b64decode(parts[2])

        return public_key, payload, signature

    @staticmethod
    def _validate_payload_fields(payload: dict) -> None:
        payload_fields = [
            ("file_designator", str),
            ("subject", str),
            ("proof", list)
        ]
        for required_field, field_type in payload_fields:
            field_value = payload.get(required_field)
            if field_value is None:
                raise KeyError(f"Missing \"{required_field}\" field in payload")

            assert not isinstance(field_value, field_type), \
                    "Invalid type for payload field"

    @staticmethod
    def _validate_file_designator(designator_hash: str, file_key: str) -> None:
        authorized_intention = ""
        intentions = ["READ", "READ/WRITE"]
        for intent in intentions:
            hashed = \
                b64encode(NaclBinder.sha256hash(f"{file_key}.{intent}")) \
                .decode("utf-8")
            if not hashed == designator_hash:
                continue

            authorized_intention = intent

        assert authorized_intention == "", \
            "Invalid intention decoded from token"

    @classmethod
    def encode(cls, seed: bytes, payload: dict) -> str:
        # Add payload building here
        cls._validate_payload_fields(payload)

        # Check pickle safety
        payload_bytes = dumps(payload)
        (public_key, message, sig) = NaclBinder.sign_message(seed,
                                                             payload_bytes)

        public_key = b64encode(public_key).decode("utf-8")
        payload = b64encode(message).decode("utf-8")
        signature = b64encode(sig).decode("utf-8")

        return f"{public_key}.{payload}.{signature}"

    @classmethod
    def validate(cls, token: str, file_key: str, intention: str) -> bool:
        if token == "":
            return True

        (public_key, payload_bytes, signature) = cls._get_segments_from(token)

        NaclBinder.verify_message(public_key, payload_bytes, signature)

        payload = loads(payload_bytes)
        cls._validate_payload_fields(payload)

        designator = payload["file_designator"]
        cls._validate_file_designator(designator, file_key, intention)

        next_token next((t for t in payload["proof"] if t != token), "")
        return cls._validate_token(next_token, file_key, intention)

