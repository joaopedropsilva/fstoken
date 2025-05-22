from pathlib import Path
from base64 import b64decode
from functools import partial

from src.nacl import NaclBinder


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
    def decrypt_to_read(pathlike: Path | str, b64key: bytes | str) -> bytes:
        filepath = Path(pathlike)
        key = b64decode(b64key)
        with open(filepath, "rb") as file:
            encrypted = file.read()

            return NaclBinder.secretbox_decrypt(encrypted, key)
    
    @classmethod
    def encrypt(cls, pathlike: Path | str, b64key: bytes | str) -> None:
        filepath = Path(pathlike)
        key = b64decode(b64key)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, key)
        cls._rewrite_file(filepath, encrypt_fn)

    @classmethod
    def decrypt(cls, pathlike: Path | str, b64key: bytes | str) -> bytes:
        filepath = Path(pathlike)
        key = b64decode(b64key)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, key)
        cls._rewrite_file(filepath, decrypt_fn)

