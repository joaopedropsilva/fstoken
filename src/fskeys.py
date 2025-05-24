from os import environ
from pathlib import Path

from src.nacl import NaclBinder


class Fskeys:
    _HOME = environ["HOME"]
    _KEYNAME = "x25519"
    DIRNAME = ".fskeys"
    DIRPATH = Path(_HOME, DIRNAME)

    @staticmethod
    def _log_if_verbose(message: str, verbose: bool) -> None:
        if verbose:
            print(message)

    @classmethod
    def init(cls, verbose: bool = False) -> None:
        cls._log_if_verbose(f"Checking for {cls.DIRNAME} existence", verbose)
        if not cls.DIRPATH.exists():
            cls._log_if_verbose(f"Creating {cls.DIRNAME}", verbose)
            cls.DIRPATH.mkdir(mode=0o700)
 
        cls._log_if_verbose("Checking for keys existence", verbose)
        should_keygen = False
        for file_ext in ["prv", "pub"]:
            key_file = Path(cls.DIRPATH, f"{cls._KEYNAME}.{file_ext}")
            if not key_file.exists():
                should_keygen = True
                key_file.touch(mode=0o600)

        if should_keygen:
            cls._log_if_verbose("Generating keys", verbose)
            (private, public) = NaclBinder.x25519_keygen()

            prv_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
            with open(prv_path, "w") as prv_file:
                prv_file.write(private.decode("utf-8"))
            pub_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.pub")
            with open(pub_path, "w") as pub_file:
                pub_file.write(public.decode("utf-8"))

        cls._log_if_verbose("Checking keystore existence", verbose)
        keystore = Path(cls.DIRPATH, Keystore.STORE_FILENAME)
        if not keystore.exists():
            cls._log_if_verbose("Creating keystore", verbose)
            Keystore.create()

    @classmethod
    def check_dir_and_contents(cls) -> None:
        assert cls.DIRPATH.exists(), \
            f"{cls.DIRNAME} does not exist"

        prv_key = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
        pub_key = Path(cls.DIRPATH, f"{cls._KEYNAME}.pub")
        assert prv_key.exists(), \
            f"{cls._KEYNAME}.prv does not exist"
        assert pub_key.exists(), \
            f"{cls._KEYNAME}.pub does not exist"
        assert prv_key.stat().st_size != 0, \
            f"{cls._KEYNAME}.prv is empty"
        assert pub_key.stat().st_size != 0, \
            f"{cls._KEYNAME}.pub is empty"

        keystore = Path(cls.DIRPATH, Keystore.STORE_FILENAME)
        assert keystore.exists(), \
            f"{Keystore.STORE_FILENAME} does not exist"


    @classmethod
    def get_keys(cls) -> tuple[str, str]:
        prv_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
        try:
            with open(prv_path, "r") as prv_file:
                prv_content = prv_file.readlines()[0].strip()
        except Exception:
            return "", ""
        private = prv_content

        pub_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
        try:
            with open(pub_path, "r") as pub_file:
                pub_content = pub_file.readlines()[0].strip()
        except Exception:
            return "", ""
        public = pub_content

        return private, public


class Keystore:
    STORE_FILENAME = "keystore.db"
    _ENTRY_DATA_SEP = "\t"

    @staticmethod
    def _get_filestring(file: str) -> str:
        return str(Path(file).resolve())

    @staticmethod
    def _create_key() -> str:
        return NaclBinder.secretbox_keygen().decode("utf-8")

    @classmethod
    def create(cls) -> None:
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        keystore.touch(mode=0o600)

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
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "r") as ks:
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
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "a") as ks:
            ks.write(cls._create_entry_repr(entry))

    @classmethod
    def _get_all_entries(cls) -> list[tuple[str, str, str]]:
        all_entries = []
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "r") as ks:
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
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "w") as ks:
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

        filekey = cls._create_key() \
                if rotate_key or not entry_exists else current_key
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

