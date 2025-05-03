from os import environ
from pathlib import Path
from base64 import b64decode
from .nacl import Crypto


class Fskeys:
    _HOME = environ["HOME"]
    _DIRNAME = ".fskeys"
    _KEYNAME = "x25519"

    @staticmethod
    def _log(message: str, verbose: bool) -> None:
        if verbose:
            print(message)

    @classmethod
    def init(cls, verbose: bool = False) -> None:
        fskeys_path = Path(cls._HOME, cls._DIRNAME)

        cls._log(f"Checking for {cls._DIRNAME} existence", verbose)
        if not fskeys_path.exists():
            cls._log(f"Creating {cls._DIRNAME}", verbose)
            fskeys_path.mkdir(mode=0o700)
 
        cls._log("Checking for keys existence", verbose)
        should_keygen = False
        for file_ext in ["prv", "pub"]:
            key_file = Path(fskeys_path, f"{cls._KEYNAME}.{file_ext}")
            if not key_file.exists():
                should_keygen = True
                key_file.touch(mode=0o600)

        if should_keygen:
            cls._log("Generating keys", verbose)
            (private, public) = Crypto.x25519_keygen(use_b64encoding=True)

            prv_path = Path(fskeys_path, f"{cls._KEYNAME}.prv")
            with open(prv_path, "w") as prv_file:
                prv_file.write(private.decode("utf-8"))
            pub_path = Path(fskeys_path, f"{cls._KEYNAME}.pub")
            with open(pub_path, "w") as pub_file:
                pub_file.write(public.decode("utf-8"))

    @classmethod
    def check_dir_and_contents(cls) -> str:
        fskeys_path = Path(cls._HOME, cls._DIRNAME)

        if not fskeys_path.exists():
            return f"{cls._DIRNAME} does not exist"

        prv_key = Path(fskeys_path, f"{cls._KEYNAME}.prv")
        pub_key = Path(fskeys_path, f"{cls._KEYNAME}.pub")

        if not prv_key.exists():
            return f"{cls._KEYNAME}.prv does not exist"
        if not pub_key.exists():
            return f"{cls._KEYNAME}.pub does not exist"

        if prv_key.stat().st_size == 0:
            return f"{cls._KEYNAME}.prv is empty"
        if pub_key.stat().st_size == 0:
            return f"{cls._KEYNAME}.pub is empty"

        return ""

    @classmethod
    def get_keys(cls) -> tuple[bytes, bytes]:
        prv_path = Path(cls._HOME, cls._DIRNAME, f"{cls._KEYNAME}.prv")
        try:
            with open(prv_path, "r") as prv_file:
                prv_content = b64decode(prv_file.readlines()[0].strip())
        except Exception:
            return bytes(), bytes()
        private = prv_content

        pub_path = Path(cls._HOME, cls._DIRNAME, f"{cls._KEYNAME}.prv")
        try:
            with open(pub_path, "r") as pub_file:
                pub_content = b64decode(pub_file.readlines()[0].strip())
        except Exception:
            return bytes(), bytes()
        public = pub_content

        return private, public

