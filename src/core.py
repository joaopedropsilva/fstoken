from os import environ
from pathlib import Path
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
    def init(cls, verbose: bool = False) -> tuple[str, bool]:
        dir_path = Path(cls._HOME, cls._DIRNAME)

        cls._log(f"Checking for {cls._DIRNAME} existence", verbose)
        if not dir_path.exists():
            cls._log(f"Creating {cls._DIRNAME}", verbose)
            dir_path.mkdir(mode=0o700)
 
        cls._log("Checking for keys existence", verbose)
        should_keygen = False
        for file_ext in ["prv", "pub"]:
            key_file = Path(dir_path, f"{cls._KEYNAME}.{file_ext}")
            if not key_file.exists():
                should_keygen = True
                key_file.touch(mode=0o600)

        if should_keygen:
            cls._log("Generating keys", verbose)
            (private, public) = Crypto.x25519_keygen(use_b64encoding=True)

            with open(Path(dir_path, f"{cls._KEYNAME}.prv"), "w") as prv_file:
                prv_file.write(private.decode("utf-8"))
            with open(Path(dir_path, f"{cls._KEYNAME}.pub"), "w") as pub_file:
                pub_file.write(public.decode("utf-8"))

        return "", True

