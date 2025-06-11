from base64 import b64encode, b64decode
from pickle import dumps, loads
from enum import Enum

from src.nacl import NaclBinder


class Grants(Enum):
    READ = "r"
    READ_WRITE = "a"

    @classmethod
    def get_available_names(cls) -> list[str]:
        return list(map(lambda k: k.lower().replace("_", "/"),
                        cls.__members__.keys()))

    @classmethod
    def map_to_available_grants(cls, incoming_grant: str) -> "Grants":
        eval_grant = incoming_grant.strip().split(" ")

        is_read = \
            True \
            if "r" in eval_grant or "read" in eval_grant \
            else False

        is_read_write = \
            True \
            if "rw" in eval_grant \
            or "read/write" in eval_grant or "write" in eval_grant \
            else False

        if not is_read and not is_read_write:
            return None

        if is_read_write:
            return cls("a")

        return cls("r")


class Token:
    """
    Implements methods to build a token in the form of
    "<public_key>.<payload>.<signature>" to promote access
    control in files, according to the given grant. 
    All token parts are encoded in Base64 by default.
    """
    _raw_payload_fields = [
        ("filekey", str),
        ("grant", str),
        ("subject", str),
        ("proof", list)
    ]
    _processed_payload_fields = [
        ("file_designator", str),
        ("subject", str),
        ("proof", list)
    ]

    @staticmethod
    def _get_file_designator_hash(filekey: str, grant: str) -> str:
        key = filekey.split("\n")[0]  # prevents malformed keystrings
        designator = f"{key}.{grant}"

        return \
            NaclBinder.sha256_hash(designator.encode("utf-8")).decode("utf-8")

    @staticmethod
    def _get_segments_from(raw_token: str) -> tuple[bytes, bytes, bytes]:
        segments = raw_token.split(".")
        assert len(segments) == 3, "Invalid token format"

        public_key = b64decode(segments[0])
        payload = b64decode(segments[1])
        signature = b64decode(segments[2])

        return public_key, payload, signature

    @staticmethod
    def _validate_payload_fields(payload: dict, payload_fields: list) -> None:
        for required_field, field_type in payload_fields:
            field_value = payload.get(required_field)
            if field_value is None:
                raise KeyError(f"Missing \"{required_field}\" field in payload")

            assert isinstance(field_value, field_type), \
                "Invalid type for payload field"

    @classmethod
    def _validate_file_designator(cls,
                                  designator: str,
                                  filekey: str) -> Grants:
        authorized_grant = None
        for grant in Grants.__iter__():
            hashed = cls._get_file_designator_hash(filekey,
                                                   repr(grant))
            if not hashed == designator:
                continue

            authorized_grant = grant

        assert authorized_grant is not None, \
            "Invalid grant or key decoded from token"

        return authorized_grant

    @classmethod
    def _build_processed_payload(cls, raw_payload: dict) -> bytes:
        cls._validate_payload_fields(raw_payload, cls._raw_payload_fields)

        grant = Grants.map_to_available_grants(raw_payload["grant"])
        assert grant is not None, \
            f"Invalid grant for file, must be: {Grants.get_available_names()}"

        processed_payload = {
            "file_designator": \
                cls._get_file_designator_hash(raw_payload["filekey"],
                                              repr(grant)),
            "subject": raw_payload["subject"],
            "proof": raw_payload["proof"]
        }

        return dumps(processed_payload)

    @classmethod
    def encode(cls, seed: str, raw_payload: dict) -> str:
        payload_bytes = cls._build_processed_payload(raw_payload)

        (public_key, message, sig) = NaclBinder.sign_message(b64decode(seed),
                                                             payload_bytes)

        public_key = b64encode(public_key).decode("utf-8")
        payload = b64encode(message).decode("utf-8")
        signature = b64encode(sig).decode("utf-8")

        return f"{public_key}.{payload}.{signature}"

    @classmethod
    def validate(cls,
                 token: str,
                 grant: Grants | None,
                 filekey: str) -> Grants:
        if token == "":
            return grant

        (public_key, payload_bytes, signature) = cls._get_segments_from(token)

        NaclBinder.verify_message(public_key, payload_bytes, signature)

        payload = loads(payload_bytes)
        cls._validate_payload_fields(payload, cls._processed_payload_fields)

        designator = payload["file_designator"]
        grant = cls._validate_file_designator(designator, filekey)

        next_token = next((t for t in payload["proof"] if t != token), "")
        return cls.validate(next_token, grant, filekey)

