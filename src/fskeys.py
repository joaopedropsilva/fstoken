from os import environ
from pathlib import Path
from base64 import b64decode

from src.file import Keystore
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

