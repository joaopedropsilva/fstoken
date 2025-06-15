from pathlib import Path

from crypto import NaclBinder
from helpers import keygen


class Keystore:
    STORE_FILENAME = "keystore.db"
    _KEYSTORE_PATH = Path("/opt/fstoken", STORE_FILENAME)
    _ENTRY_DATA_SEP = "\t"

    @staticmethod
    def _get_filestring(file: str) -> str:
        return str(Path(file).resolve())

    @classmethod
    def _create_entry_repr(cls, entry: tuple[str, str, str]) -> str:
        (filestring, encstring, keystring) = entry

        return filestring \
                + cls._ENTRY_DATA_SEP \
                + encstring \
                + cls._ENTRY_DATA_SEP \
                + keystring \
                + "\n"

    @classmethod
    def search_entry_state(cls, file: str) -> tuple[bool, str]:
        with open(cls._KEYSTORE_PATH, "r") as ks:
            entries = list(map(lambda line: line.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            for entry in entries:
                if len(entry) != 3:
                    continue
                (filestring, encstring, keystring) = entry
                if filestring == cls._get_filestring(file):
                    encrypted = True if encstring == "1" else False
                    return encrypted, keystring

        return False, ""

    @classmethod
    def _append(cls, entry: tuple[str, str, str]) -> None:
        with open(cls._KEYSTORE_PATH, "a") as ks:
            ks.write(cls._create_entry_repr(entry))

    @classmethod
    def _get_all_entries(cls) -> list[tuple[str, str, str]]:
        all_entries = []
        with open(cls._KEYSTORE_PATH, "r") as ks:
            entries = list(map(lambda l: l.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            for entry in entries:
                if len(entry) != 3:
                    continue

                all_entries.append(entry)

        return all_entries

    @classmethod
    def _truncate_and_rewrite_lines(
            cls, entries: list[tuple[str, str, str]]) -> None:
        with open(cls._KEYSTORE_PATH, "w") as ks:
            for entry in entries:
                ks.write(cls._create_entry_repr(entry))

    @classmethod
    def change_entry(cls,
                     file: str,
                     encrypt: bool = False,
                     rotate_key: bool = False,
                     delete: bool = False) -> str:
        (_, current_key) = cls.search_entry_state(file)
        entry_exists = current_key != ""

        filekey = keygen() if rotate_key or not entry_exists else current_key
        new_entry = (cls._get_filestring(file), 
                     "1" if encrypt else "0",
                     filekey)

        if not entry_exists:
            cls._append(new_entry)

            return filekey

        new_entries = [er for er in cls._get_all_entries() \
                       if er[0] != new_entry[0]]

        if not delete:
            new_entries.append(new_entry)

        cls._truncate_and_rewrite_lines(new_entries)

        return filekey

