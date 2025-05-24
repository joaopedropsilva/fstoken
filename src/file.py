from pathlib import Path
from functools import partial

from src.nacl import NaclBinder
from src.helpers import log


class File:
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
            log_if_verbose(
                f"Unable to decrypt: {args.file}, operation not permitted",
                verbose=True
            )
            return ""

    @classmethod
    def encrypt(cls, file: str, b64key: bytes | str) -> bool:
        filepath = Path(file)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, b64key)
        try:
            cls._rewrite_file(filepath, encrypt_fn)
        except PermissionError:
            log_if_verbose(
                f"Unable to encrypt: {args.file}, operation not permitted",
                verbose=True
            )
            return False

        return True

    @classmethod
    def decrypt(cls, file: str, b64key: bytes | str) -> bool:
        filepath = Path(file)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, b64key)
        try:
            cls._rewrite_file(filepath, decrypt_fn)
        except PermissionError:
            log_if_verbose(
                f"Unable to decrypt: {args.file}, operation not permitted",
                verbose=True
            )
            return False

        return True

