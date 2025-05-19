from pathlib import Path
from base64 import b64decode
from functools import partial

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
    def check_entry(cls,
                    fskeys_dir: Path,
                    filepath: Path) -> tuple[str, bool, str]:
        keystore = Path(fskeys_dir, cls.STORE_FILENAME)
        with open(keystore, "r") as ks:
            entries = list(map(lambda line: line.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            for entry in entries:
                if len(entry) != 3:
                    continue

                (file_repr, enc_repr, keystring) = entry
                if file_repr == cls._get_file_repr(filepath):
                    is_encrypted = True if enc_repr == "1" else False
                    return file_repr, is_encrypted, keystring

        return "", False, ""

    @classmethod
    def create_entry(cls,
                     fskeys_dir: Path,
                     entry_data: tuple[Path, bool, bytes]) -> None:
        file_repr = cls._get_file_repr(entry_data[0])
        enc_repr = cls._get_enc_repr(entry_data[1])
        keystring = cls._get_keystring(entry_data[2])

        keystore = Path(fskeys_dir, cls.STORE_FILENAME)
        with open(keystore, "a") as ks:
            entry = file_repr \
                    + cls._ENTRY_DATA_SEP \
                    + enc_repr \
                    + cls._ENTRY_DATA_SEP \
                    + keystring \
                    + "\n"
            ks.write(entry)

    @classmethod
    def remove_entry(cls, fskeys_dir: Path, filepath: Path) -> None:
        keystore = Path(fskeys_dir, cls.STORE_FILENAME)
        with open(keystore, "r+") as ks:
            entries = list(map(lambda l: l.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            target_entry = None
            for index, entry in enumerate(entries):
                (file_repr, _, _) = entry
                if file_repr == cls._get_file_repr(filepath):
                    target_entry = entry

            if target_entry is None:
                return

            new_entries = entries
            new_entries.remove(target_entry)

            ks.seek(0)
            ks.truncate(0)
            for (file_repr, enc_repr, keystring) in new_entries:
                entry = file_repr \
                        + cls._ENTRY_DATA_SEP \
                        + enc_repr \
                        + cls._ENTRY_DATA_SEP \
                        + keystring \
                        + "\n"
                ks.write(entry)


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
    def decrypt_to_read(filepath: Path, b64key: bytes | str) -> bytes:
        key = b64decode(b64key)
        with open(filepath, "rb") as file:
            encrypted = file.read()

            return NaclBinder.secretbox_decrypt(encrypted, key)

    @staticmethod
    def create_key() -> bytes:
        return NaclBinder.secretbox_keygen(use_b64encoding=True)
    
    @classmethod
    def encrypt(cls, filepath: Path, b64key: bytes | str) -> None:
        key = b64decode(b64key)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, key)
        cls._rewrite_file(filepath, encrypt_fn)

    @classmethod
    def decrypt(cls, filepath: Path, b64key: bytes | str) -> bytes:
        key = b64decode(b64key)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, key)
        cls._rewrite_file(filepath, decrypt_fn)

