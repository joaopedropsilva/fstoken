from argparse import ArgumentParser
from pathlib import Path

from src.fskeys import Fskeys
from src.token import Token
from src.file import Keystore, File


def _require_init_before_exec() -> None:
    Fskeys.check_dir_and_contents()


def init() -> None:
    Fskeys.init(verbose=True)


def add(filestring: str, should_encrypt: bool) -> None:
    _require_init_before_exec()

    assert filestring != "", "A file must be passed to use this command"

    filepath = Path(filestring)
    assert filepath.exists(), "The file must exist to use this command"

    (file, _, _) = \
            Keystore.check_entry(Fskeys.DIRPATH, filepath)
    if file != "":
        print("File already exists in keystore")
        return

    filekey = File.create_key()
    if should_encrypt:
        File.encrypt(filepath, filekey)

    entry_data = (filepath, should_encrypt, filekey)
    Keystore.create_entry(Fskeys.DIRPATH, entry_data)


def remove(filestring: str) -> None:
    _require_init_before_exec()

    assert filestring != "", "A file must be passed to use this command"

    filepath = Path(filestring)
    (file, is_encrypted, filekey) = \
            Keystore.check_entry(Fskeys.DIRPATH, filepath)
    if file == "":
        print("File not found in keystore")
        return

    if is_encrypted:
        File.decrypt(filepath, filekey)

    Keystore.remove_entry(Fskeys.DIRPATH, filepath)


def tokenize(file: str, extra: str) -> None:
    _require_init_before_exec()

    # get file_key based on ownership
    # sugest file encryption
    file_key = ""
    # Retrieve from cli
    subject = \
        input("Delegate access to: ").strip().upper()
    grant = \
        input("Grant access of [READ | READ/WRITE]: ").strip().upper()
    delegated_token = ""

    (private, public) = Fskeys.get_keys()
    token = Token.encode(private, raw_payload={"file_key": file,
                                               "grant": grant,
                                               "subject": subject,
                                               "proof": [delegated_token]})

    print("Token generated:")
    print(f"{token}")


if __name__ == "__main__":
    parser = ArgumentParser(prog="fstoken",
                            description="A command line tool that enables " \
                            "file access control using a semi capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("file", nargs="?", default="")
    parser.add_argument("grant", nargs="?", default="READ")
    parser.add_argument("token", nargs="?", default="")
    parser.add_argument("--encrypt", "-e", action="store_true")
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "add":
        add(args.file, args.encrypt)
    elif args.command == "remove":
        remove(args.file)
    elif args.command == "delegate":
        tokenize(args.file)
    elif args.command == "invoke":
        decode(args.token)
    elif args.command == "revoke":
        pass
    else:
        print("Command does not exist")

