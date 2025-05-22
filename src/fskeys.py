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
    def _get_file_repr(pathlike: Path | str) -> str:
        filepath = Path(pathlike)
        return str(filepath.resolve())

    @staticmethod
    def _create_key() -> bytes:
        return NaclBinder.secretbox_keygen(use_b64encoding=True)

    @classmethod
    def _create_entry_repr(cls,
                           filestring: str,
                           is_encrypted: bool | str,
                           key: bytes | str) -> str:
        file_repr = cls._get_file_repr(filestring)
        enc_repr = is_encrypted
        if not isinstance(is_encrypted, str):
            enc_repr = "1" if is_encrypted else "0"
        keystring = key
        if not isinstance(key, str):
            keystring = key.decode("utf-8")

        return file_repr \
                + cls._ENTRY_DATA_SEP \
                + enc_repr \
                + cls._ENTRY_DATA_SEP \
                + keystring \
                + "\n"

    @classmethod
    def create(cls) -> None:
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        keystore.touch(mode=0o600)

    @classmethod
    def _search(cls, filestring: str) -> tuple[Path | None, bool, bytes]:
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "r") as ks:
            entries = list(map(lambda line: line.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            for entry in entries:
                if len(entry) != 3:
                    continue
                (file_repr, enc_repr, keystring) = entry
                if file_repr == cls._get_file_repr(filestring):
                    is_encrypted = True if enc_repr == "1" else False
                    return Path(file_repr), is_encrypted, b64decode(keystring)

        return None, False, bytes()

    @classmethod
    def _append(cls, filestring: str, is_encrypted: bool, key: bytes) -> None:
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "a") as ks:
            entry = cls._create_entry_repr(filestring, is_encrypted, key)
            ks.write(entry)

    @classmethod
    def update_or_remove_entry(cls,
                               filestring: str,
                               new_encryption_state: bool = None,
                               new_key: bytes = None) -> tuple[str, bool, str]:
        keystore = Path(Fskeys.DIRPATH, cls.STORE_FILENAME)
        with open(keystore, "r+") as ks:
            entries = list(map(lambda l: l.split(cls._ENTRY_DATA_SEP),
                               ks.readlines()))

            old_entry = None
            for index, entry in enumerate(entries):
                if len(entry) != 3:
                    continue

                (file_repr, _, _) = entry
                if file_repr == cls._get_file_repr(filestring):
                    old_entry = entry
            if old_entry is None:
                return

            new_entries = [e for e in entries
                           if len(e) == 3 and e != old_entry]

            old_entry_updated = None
            if new_encryption_state is not None:
                old_entry_updated = cls._create_entry_repr(old_entry[0],
                                                           new_encryption_state,
                                                           old_entry[2])
            elif new_key is not None:
                old_entry_updated = cls._create_entry_repr(old_entry[0],
                                                           old_entry[1],
                                                           new_key)

            if old_entry_updated is not None:
                new_entries.append(old_entry_updated)

            ks.seek(0)
            ks.truncate(0)
            for file_repr, enc_repr, keystring in new_entries:
                entry = cls._create_entry_repr(file_repr, enc_repr, keystring)
                ks.write(entry)

            (filestring, enc_repr, keystring) = old_entry_updated
            return filestring, True if enc_repr == "1" else 0, keystring

    @classmethod
    def add(cls,
            filestring: str,
            should_encrypt: bool) -> tuple[Path, bool, bytes]:
        (file_stored, enc_stored, key_stored) = cls._search(filestring)

        filekey = cls._create_key() if file_stored is None else key_stored

        if file_stored is None:
            cls._append(filestring, should_encrypt, filekey)
            return Path(filestring), should_encrypt, filekey

        if should_encrypt != enc_stored:
            cls.update_or_remove_entry(filestring, should_encrypt)
            return file_stored, should_encrypt, key_stored

        return file_stored, enc_stored, filekey

