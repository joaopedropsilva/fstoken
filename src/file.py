from pathlib import Path
from os import access, W_OK, X_OK
from subprocess import run, CalledProcessError
from functools import partial

from crypto import NaclBinder


class  File:
    _FSTOKEN_USER = "fstoken"

    @staticmethod
    def _rewrite_file(filepath: Path, content_producer_fn: callable) -> None:
        with open(filepath, "r+b") as file:
            content = file.read()
            file.seek(0)
            file.truncate(0)

            reprocessed = content_producer_fn(content)
            file.write(reprocessed)

    @staticmethod
    def decrypt_to_read(file: str, b64key: bytes | str) -> str:
        filepath = Path(file)
        with open(filepath, "rb") as file:
            encrypted = file.read()

            return NaclBinder.secretbox_decrypt(b64key, encrypted) \
                .decode("utf-8")

    @staticmethod
    def _get_accessible_candidates(file: str) -> list[str]:
        stop_dirname = "/"
        pathnames = []
        path = Path(file).parent
        while True:
            # Iterate dirs until user has no access
            if str(path) == stop_dirname or not access(path, W_OK | X_OK):
                break

            pathnames.append(str(path.resolve()))
            path = Path(path).parent

        return pathnames

    @classmethod
    def decrypt(cls, file: str, b64key: bytes | str) -> None:
        filepath = Path(file)
        decrypt_fn = partial(NaclBinder.secretbox_decrypt, b64key)
        cls._rewrite_file(filepath, decrypt_fn)

    @classmethod
    def encrypt(cls, file: str, b64key: bytes | str) -> None:
        filepath = Path(file)
        encrypt_fn = partial(NaclBinder.secretbox_encrypt, b64key)
        cls._rewrite_file(filepath, encrypt_fn)

    @classmethod
    def _remove_dir_acls(cls, pathnames: list[str]) -> str:
        for p in pathnames:
            try:
                run(["setfacl", "-x", f"u:{cls._FSTOKEN_USER}", p], check=True)
            except CalledProcessError:
                return f"Failed to revoke fstoken user access to: {p}"

        return ""

    @classmethod
    def _add_dir_acls(cls, pathnames: list[str]) -> str:
        failed_index = 0
        for idx, p in enumerate(pathnames):
            try:
                failed_index = idx
                run(["setfacl", "-m", f"u:{cls._FSTOKEN_USER}:wx", p], check=True)
            except CalledProcessError:
                grant_err = f"Failed to grant fstoken user access to: {p}"
                removal_failure = cls._remove_dir_acls(pathnames[:failed_index])
                if removal_failure:
                    grant_err += \
                        f"\nAnother error occurred removing previously granted acls:" \
                        f"\n{removal_failure}"
                return grant_err

        return ""

    @classmethod
    def grant_fstoken_access(cls, file: str) -> str:
        try:
            with open(file, "r+") as f:
                pass
        except PermissionError:
            return "User must have rw- access on file to add it to fstoken"

        try:
            run(["setfacl", "-m", f"u:{cls._FSTOKEN_USER}:rw-", file], check=True)
        except CalledProcessError:
             return f"Failed to grant fstoken user access to: {file}"

        pathnames_to_add = cls._get_accessible_candidates(file)

        addition_err = cls._add_dir_acls(pathnames_to_add)
        if addition_err:
            return addition_err

        return ""

    @classmethod
    def revoke_fstoken_access(cls, file: str) -> str:
        err_revocation = ""
        try:
            run(["setfacl", "-x", f"u:{cls._FSTOKEN_USER}", file], check=True)
        except CalledProcessError:
            err_revocation = f"Failed to revoke fstoken user access to: {file}"

        pathnames_to_remove = cls._get_accessible_candidates(file)

        cls._remove_dir_acls(pathnames_to_remove) # Ignoring likely access errors

        return err_revocation

