from argparse import Namespace
from pathlib import Path

from src.nacl import NaclBinder
from src.token import Token
from src.file import File
from src.helpers import log


class Keystore:
    STORE_FILENAME = "keystore.db"
    KEYSTORE_PATH = Path("/run/fstokend", STORE_FILENAME)
    _ENTRY_DATA_SEP = "\t"

    @staticmethod
    def _get_filestring(file: str) -> str:
        return str(Path(file).resolve())

    @staticmethod
    def _create_key() -> str:
        return NaclBinder.secretbox_keygen().decode("utf-8")

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
    def _search_entry_state(cls, file: str) -> tuple[bool, str]:
        with open(KEYSTORE_PATH, "r") as ks:
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
        with open(KEYSTORE_PATH, "a") as ks:
            ks.write(cls._create_entry_repr(entry))

    @classmethod
    def _get_all_entries(cls) -> list[tuple[str, str, str]]:
        all_entries = []
        with open(KEYSTORE_PATH, "r") as ks:
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
        with open(KEYSTORE_PATH, "w") as ks:
            for entry in entries:
                ks.write(cls._create_entry_repr(entry))

    @classmethod
    def _change_entry(cls,
                     file: str,
                     encrypt: bool = False,
                     rotate_key: bool = False,
                     delete: bool = False) -> str:
        (_, current_key) = cls._search_entry_state(file)
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

    def _handle_deletion(args: Namespace,
                         was_encrypted: bool,
                         filekey: str) -> None:
        if prev_key == "":
            log(f"File not found in {Keystore.STORE_FILENAME}", args.verbose)
            exit(1)

        log(f"Removing from {Keystore.STORE_FILENAME}", args.verbose)
        Keystore._change_entry(args.file, delete=True)

        if was_encrypted:
            File.decrypt(args.file, filekey)

    def _handle_invocation(args: Namespace,
                           was_encrypted: bool,
                           filekey: str) -> None:
        try:
            validity = Token.validate(args.token, filekey)
            print(f"valid: {validity}")
        except (AssertionError, KeyError) as err:
            log(err, verbose=True)

    def _handle_delegation(args: Namespace, filekey: str) -> None:
        (private, _) = Fskeys.get_keys()
        try:
            token = Token.encode(private, raw_payload={"filekey": filekey,
                                                       "grant": args.grant,
                                                       "subject": args.subject,
                                                       "proof": [args.token]})
        except (AssertionError, KeyError) as err:
            log(err, verbose=True)
            return

        print(token)

    def change(args: Namespace) -> None:
        (was_encrypted, prevkey) = Keystore._search_entry_state(args.file)

        is_deletion = args.delete
        is_delegation = args.grant and args.subject
        is_invocation = args.token and not is_delegation

        if is_deletion:
            _handle_deletion(args, was_encrypted, prevkey)
        if is_invocation:
            _handle_invocation(args, was_encrypted, prevkey)

        newkey = Keystore._change_entry(args.file,
                                       encrypt=args.encrypt,
                                       rotate_key=args.rotate,
                                       delete=False)

        if was_encrypted:
            File.decrypt(args.file, prevkey)
            return
        if args.encrypt:
            File.encrypt(args.file, newkey)
            return

        if is_delegation:
            _handle_delegation(args, newkey)

