from os import environ
from pathlib import Path
from base64 import b64decode

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
            (private, public) = NaclBinder.x25519_keygen(use_b64encoding=True)

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
            Keystore.create(cls.DIRPATH)

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
    def get_keys(cls) -> tuple[bytes, bytes]:
        prv_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
        try:
            with open(prv_path, "r") as prv_file:
                prv_content = b64decode(prv_file.readlines()[0].strip())
        except Exception:
            return bytes(), bytes()
        private = prv_content

        pub_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
        try:
            with open(pub_path, "r") as pub_file:
                pub_content = b64decode(pub_file.readlines()[0].strip())
        except Exception:
            return bytes(), bytes()
        public = pub_content

        return private, public


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
    def _get_full_entry_repr(cls,
                             file_repr: str,
                             enc_repr: str,
                             keystring: str) -> str:
        return file_repr \
                + cls._ENTRY_DATA_SEP \
                + enc_repr \
                + cls._ENTRY_DATA_SEP \
                + keystring \
                + "\n"

    @classmethod
    def create(cls, parent: Path) -> None:
        keystore = Path(parent, cls.STORE_FILENAME)
        keystore.touch(mode=0o600)

    @classmethod
    def search_entry(cls,
                     parent: Path,
                     filepath: Path) -> tuple[str, bool, str]:
        keystore = Path(parent, cls.STORE_FILENAME)
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
                     parent: Path,
                     entry_data: tuple[Path, bool, bytes]) -> None:
        file_repr = cls._get_file_repr(entry_data[0])
        enc_repr = cls._get_enc_repr(entry_data[1])
        keystring = cls._get_keystring(entry_data[2])

        keystore = Path(parent, cls.STORE_FILENAME)
        with open(keystore, "a") as ks:
            entry = cls._get_full_entry_repr(file_repr, enc_repr, keystring)
            ks.write(entry)

    @classmethod
    def remove_entry(cls, parent: Path, filepath: Path) -> None:
        keystore = Path(parent, cls.STORE_FILENAME)
        with open(keystore, "r+") as ks:
            entries = list(map(lambda l: l.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            target_entry = None
            for index, entry in enumerate(entries):
                if len(entry) != 3:
                    continue

                (file_repr, _, _) = entry
                if file_repr == cls._get_file_repr(filepath):
                    target_entry = entry
            if target_entry is None:
                return

            new_entries = [e for e in entries
                           if len(e) == 3 and e != target_entry]

            ks.seek(0)
            ks.truncate(0)
            for file_repr, enc_repr, keystring in new_entries:
                entry = cls._get_full_entry_repr(file_repr, enc_repr, keystring)
                ks.write(entry)

