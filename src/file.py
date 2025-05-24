from pathlib import Path
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
    def decrypt_to_read(file: str, b64key: bytes | str) -> bytes:
        filepath = Path(pathlike)
        with open(filepath, "rb") as file:
            encrypted = file.read()

            return NaclBinder.secretbox_decrypt(encrypted, b64key)
    
    @classmethod
    def encrypt(cls, file: str, b64key: bytes | str) -> None:
        filepath = Path(file)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, b64key)
        cls._rewrite_file(filepath, encrypt_fn)

    @classmethod
    def decrypt(cls, file: str, b64key: bytes | str) -> bytes:
        filepath = Path(file)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, b64key)
        cls._rewrite_file(filepath, decrypt_fn)

