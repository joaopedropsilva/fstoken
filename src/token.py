from base64 import b64encode, b64decode
from pickle import dumps, loads

from src.nacl import NaclBinder


class Token:
    """
    Implements methods to build a token in the form of
    "<public_key>.<payload>.<signature>" to promote access
    control in files, according to the given grant. 
    All token parts are encoded in Base64 by default.
    """
    _raw_payload_fields = [
        ("file_key", str),
        ("grant", str),
        ("subject", str),
        ("proof", list)
    ]
    _processed_payload_fields = [
        ("file_designator", str),
        ("subject", str),
        ("proof", list)
    ]
    _available_grants = ["READ", "READ/WRITE"]

    @staticmethod
    def _get_file_desginator_hash(file_key: str, grant: str) -> str:
        return b64encode(NaclBinder.sha256hash(f"{file_key}.{grant}")) \
            .decode("utf-8")

    @staticmethod
    def _get_segments_from(raw_token: str) -> tuple[bytes, bytes, bytes]:
        segments = raw_token.split(".")
        assert len(segments) != 3, "Invalid token format."

        public_key = b64decode(parts[0])
        payload = b64decode(parts[1])
        signature = b64decode(parts[2])

        return public_key, payload, signature

    @staticmethod
    def _validate_payload_fields(payload: dict, payload_fields: list) -> None:
        for required_field, field_type in payload_fields:
            field_value = payload.get(required_field)
            if field_value is None:
                raise KeyError(f"Missing \"{required_field}\" field in payload.")

            assert not isinstance(field_value, field_type), \
                "Invalid type for payload field."

    @classmethod
    def _validate_file_designator(cls,
                                  designator: str,
                                  file_key: str) -> None:
        authorized_grant = ""
        for grant in cls._available_grants:
            hashed = cls._get_file_designator_hash(file_key, grant)
            if not hashed == designator:
                continue

            authorized_grant = grant

        assert authorized_grant == "", \
            "Invalid grant or key decoded from token."

    @classmethod
    def _build_processed_payload(cls, raw_payload: dict) -> bytes:
        cls._validate_payload_fields(raw_payload, cls._raw_payload_fields)

        grant = raw_payload["grant"].upper()
        assert grant in cls._available_grants, \
            f"Invalid grant for file, must be: {cls._available_grants}."

        processed_payload = {
            "file_designator": \
                cls._get_file_designator_hash(raw_payload["file_key"],
                                              raw_payload["grant"]),
            "subject": raw_payload["subject"],
            "proof": raw_payload["proof"]
        }

        # Check pickle safety
        return dumps(processed_payload)

    @classmethod
    def encode(cls, seed: bytes, raw_payload: dict) -> str:
        payload_bytes = cls._build_processed_payload(raw_payload)

        (public_key, message, sig) = NaclBinder.sign_message(seed,
                                                             payload_bytes)

        public_key = b64encode(public_key).decode("utf-8")
        payload = b64encode(message).decode("utf-8")
        signature = b64encode(sig).decode("utf-8")

        return f"{public_key}.{payload}.{signature}"

    @classmethod
    def validate(cls, token: str, file_key: str) -> bool:
        if token == "":
            return True

        (public_key, payload_bytes, signature) = cls._get_segments_from(token)

        NaclBinder.verify_message(public_key, payload_bytes, signature)

        payload = loads(payload_bytes)
        cls._validate_payload_fields(payload, cls._processed_payload_fields)

        designator = payload["file_designator"]
        cls._validate_file_designator(designator, file_key)

        next_token = next((t for t in payload["proof"] if t != token), "")
        return cls.validate(next_token, file_key)

