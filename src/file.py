from pathlib import Path
from base64 import b64decode

from src.nacl import NaclBinder


class Keystore:
    STORE_FILENAME = "keystore.db"
    _ENTRY_DATA_SEP = "\t"

    @staticmethod
    def _get_file_repr(filepath: Path) -> str:
        return str(filepath.resolve())

    @staticmethod
    def _get_enc_repr(is_encrypted: bool) -> str:
        return "1" if is_encrypted else "0"

    @staticmethod
    def _get_keystring(key: bytes) -> str:
        return key.decode("utf-8")

    @classmethod
    def create(cls, fskeys_dir: Path) -> None:
        keystore = Path(fskeys_dir, cls.STORE_FILENAME)
        keystore.touch(mode=0o600)

    @classmethod
    def check_entry_existence(cls, fskeys_dir: Path, filepath: Path) -> bool:
        keystore = Path(fskeys_dir, cls.STORE_FILENAME)
        with open(keystore, "r") as ks:
            entries = list(
                map(lambda line: line.split(cls._ENTRY_DATA_SEP),
                    ks.readlines())
            )

            for file_repr, _, _ in entries:
                if file_repr == cls._get_file_repr(filepath):
                    return True
        return False

    @classmethod
    def create_entry(cls,
                     fskeys_dir: Path,
                     entry_data: tuple[Path, bool, bytes]) -> None:
        file_repr = cls._get_file_repr(entry_data[0])
        enc_repr = cls._get_enc_repr(entry_data[1])
        keystring = cls._get_keystring(entry_data[2])

        keystore = Path(fskeys_dir, cls.STORE_FILENAME)
        with open(keystore, "a") as ks:
            line = file_repr \
                    + cls._ENTRY_DATA_SEP \
                    + enc_repr \
                    + cls._ENTRY_DATA_SEP \
                    + keystring
            ks.write(line)


class File:
    @staticmethod
    def encrypt(filepath: Path, b64key: bytes) -> None:
        key = b64decode(b64key)
        with open(filepath, "r+b") as file:
            content = file.read()
            file.seek(0)
            file.truncate(0)

            encrypted = NaclBinder.secretbox_encrypt(content, key)
            file.write(encrypted)

    @staticmethod
    def decrypt_to_read(filepath: Path, b64key: bytes) -> bytes:
        key = b64decode(b64key)
        with open(filepath, "rb") as file:
            encrypted = file.read()

            return NaclBinder.secretbox_decrypt(encrypted, key)

    @staticmethod
    def create_key() -> bytes:
        return NaclBinder.secretbox_keygen(use_b64encoding=True)

