from os import environ
from pathlib import Path

from crypto import NaclBinder
from helpers import log


class Fskeys:
    _HOME = environ["HOME"]
    _KEYNAME = "x25519"
    DIRNAME = ".fskeys"
    DIRPATH = Path(_HOME, DIRNAME)

    @classmethod
    def init(cls) -> None:
        log(f"Checking for {cls.DIRNAME} existence")
        if not cls.DIRPATH.exists():
            log(f"Creating {cls.DIRNAME}")
            cls.DIRPATH.mkdir(mode=0o700)
 
        log("Checking for keys existence")
        should_keygen = False
        for file_ext in ["prv", "pub"]:
            key_file = Path(cls.DIRPATH, f"{cls._KEYNAME}.{file_ext}")
            if not key_file.exists():
                should_keygen = True
                key_file.touch(mode=0o600)

        if should_keygen:
            log("Generating keys")
            (private, public) = NaclBinder.x25519_keygen()

            prv_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.prv")
            with open(prv_path, "w") as prv_file:
                prv_file.write(private.decode("utf-8"))
            pub_path = Path(cls.DIRPATH, f"{cls._KEYNAME}.pub")
            with open(pub_path, "w") as pub_file:
                pub_file.write(public.decode("utf-8"))

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

