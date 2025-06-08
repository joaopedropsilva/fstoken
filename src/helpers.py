from sys import stderr
from typing import NewType


OpResult = NewType("OpResult", tuple[str, str])


def log(message: str) -> None:
    print(message)


def log_err(message: str) -> None:
    if message == "":
        return
    print(message, file=stderr)

