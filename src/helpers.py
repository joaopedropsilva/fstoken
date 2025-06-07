from sys import stderr
from typing import NewType


def log(message: str, verbose: bool) -> None:
    if not verbose:
        return
    print(message, file)


def log_err(message: str) -> None:
    print(message, file=stderr)

