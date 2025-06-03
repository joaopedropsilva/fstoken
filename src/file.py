from pathlib import Path
from subprocess import run, CalledProcessError
from functools import partial

from src.nacl import NaclBinder
from src.helpers import log


class File:
    _FSTOKEN_USER = "fstoken"
    _OP_NOT_PERMITTED_MSG = \
        "Unable to {op} file: {file} (operation not permitted)\n" \
        "Make sure you have the correct access rights to perform this operation"

    @staticmethod
    def _rewrite_file(filepath: Path, content_producer_fn: callable) -> None:
        with open(filepath, "r+b") as file:
            content = file.read()
            file.seek(0)
            file.truncate(0)

            reprocessed = content_producer_fn(content)
            file.write(reprocessed)

    @staticmethod
    def decrypt_to_read(file: str, b64key: bytes | str) -> str:
        filepath = Path(pathlike)
        try:
            with open(filepath, "rb") as file:
                encrypted = file.read()

                return NaclBinder.secretbox_decrypt(encrypted, b64key) \
                        .decode("utf-8")
        except PermissionError:
            log(cls._OP_NOT_PERMITTED_MSG.format(op="decrypt", file=file),
                verbose=True)
            return ""

    @classmethod
    def decrypt(cls, file: str, b64key: bytes | str) -> bool:
        filepath = Path(file)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, b64key)
        try:
            cls._rewrite_file(filepath, decrypt_fn)
        except PermissionError:
            log(cls._OP_NOT_PERMITTED_MSG.format(op="decrypt", file=file),
                verbose=True)
            return False

        return True

    @classmethod
    def encrypt(cls, file: str, b64key: bytes | str) -> bool:
        filepath = Path(file)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, b64key)
        try:
            cls._rewrite_file(filepath, encrypt_fn)
        except PermissionError:
            log(cls._OP_NOT_PERMITTED_MSG.format(op="encrypt", file=file),
                verbose=True)
            return False

        return True

    @classmethod
    def grant_fstoken_access(cls, file: str) -> None:
        file = str(Path(file).resolve())
        try:
            run(["setfacl", "-m", f"u:{cls._FSTOKEN_USER}:rw-", file],
                check=True)
        except CalledProcessError:
            log(f"Failed to grant fstoken user access to file: {file}",
                verbose=True)

    @classmethod
    def revoke_fstoken_access(cls, file: str) -> None:
        filepath = Path(file)
        try:
            run(["setfacl", "-x", f"u:{cls._FSTOKEN_USER}", file],
                check=True)
        except CalledProcessError:
            log(f"Failed to revoke fstoken user access to file: {file}",
                verbose=True)

