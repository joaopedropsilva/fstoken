from pathlib import Path
from subprocess import run, CalledProcessError
from functools import partial

from src.nacl import NaclBinder


class  File:
    _FSTOKEN_USER = "fstoken"

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
        with open(filepath, "rb") as file:
            encrypted = file.read()

            return NaclBinder.secretbox_decrypt(encrypted, b64key) \
                .decode("utf-8")

    @classmethod
    def decrypt(cls, file: str, b64key: bytes | str) -> None:
        filepath = Path(file)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, b64key)
        cls._rewrite_file(filepath, decrypt_fn)

    @classmethod
    def encrypt(cls, file: str, b64key: bytes | str) -> None:
        filepath = Path(file)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, b64key)
        cls._rewrite_file(filepath, encrypt_fn)

    @classmethod
    def grant_fstoken_access(cls, file: str) -> str:
        file = str(Path(file).resolve())
        try:
            run(["setfacl", "-m", f"u:{cls._FSTOKEN_USER}:rw-", file],
                check=True)
        except CalledProcessError:
            return f"Failed to grant fstoken user access to file: {file}"

        return ""

    @classmethod
    def revoke_fstoken_access(cls, file: str) -> str:
        filepath = Path(file)
        try:
            run(["setfacl", "-x", f"u:{cls._FSTOKEN_USER}", file],
                check=True)
        except CalledProcessError:
            return f"Failed to revoke fstoken user access to file: {file}"

        return ""

