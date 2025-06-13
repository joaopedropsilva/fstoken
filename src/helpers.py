from sys import stderr
from typing import NewType
from pickle import loads, dumps


def log(message: str) -> None:
    print(message)


def log_err(message: str) -> None:
    if message == "":
        return
    print(message, file=stderr)


class Message:
    @classmethod
    def from_bytes(cls, as_bytes: bytes) -> "Message":
        obj = loads(as_bytes)
        return cls(obj.payload, obj.err)

    def __init__(self, payload: any, err: str, hide_payload: bool = True):
        self._payload = payload
        self._hide_payload = hide_payload
        self._err = err

    def __bytes__(self) -> bytes:
        return dumps(self)

    @property
    def payload(self) -> any:
        return self._payload

    @property
    def err(self) -> str:
        return self._err

    def get_exposable_payload(self) -> str:
        if self._hide_payload or not self._payload:
            return ""

        return str(self._payload)

