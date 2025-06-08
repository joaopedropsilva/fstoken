from sys import stderr
from typing import NewType
from pickle import loads, dumps


OpResult = NewType("OpResult", tuple[str, str])


def log(message: str) -> None:
    print(message)


def log_err(message: str) -> None:
    if message == "":
        return
    print(message, file=stderr)


class SocketMessage:
    @classmethod
    def from_bytes(cls, as_bytes: bytes) -> "SocketMessage":
        obj = loads(as_bytes)
        return cls(obj.payload, obj.err)

    def __init__(self, payload: any, err: str):
        self._payload = payload
        self._err = err

    def __bytes__(self) -> bytes:
        return dumps(self)

    @property
    def payload(self) -> any:
        return self._payload

    @property
    def err(self) -> str:
        return self._err

