from argparse import ArgumentParser, Namespace
from pathlib import Path

from src.fskeys import Fskeys, Keystore
from src.token import Token
from src.file import File


def _require_init_before_exec() -> None:
    Fskeys.check_dir_and_contents()


def init() -> None:
    Fskeys.init(verbose=True)


def add_or_delegate(args: Namespace) -> None:
    _require_init_before_exec()

    # validate if file belongs to user
    if args.file == "":
        print("A file must be passed to use this command")

    (filepath, _, key) = Keystore.add(args.file, args.encrypt)

    if args.encrypt:
        File.encrypt(filepath, key)
    else:
        pass
        # File was just added with args.encrypt 0 will break here
        # there is a need to clarify intention to run this operation
        # according to what happened before
        #File.decrypt(filepath, key)

    if args.grant == "" or args.subject == "":
        return

    (private, _) = Fskeys.get_keys()
    token = Token.encode(private, raw_payload={"file_key": key.decode("utf-8"),
                                               "grant": args.grant,
                                               "subject": args.subject,
                                               "proof": [args.token]})
    print(token)


def remove(filestring: str) -> None:
    _require_init_before_exec()

    if filestring == "":
        print("A file must be passed to use this command")

    (_, was_encrypted, key) = Keystore.update_or_remove_entry(filestring)
    if was_encrypted:
        File.decrypt(filestring, key)


def invoke(filestring: str, token: str) -> None:
    # Token eval
    pass


def revoke(filestring: str) -> None:
    # Key rotate
    pass


if __name__ == "__main__":
    parser = ArgumentParser(prog="fstoken",
                            description="A command line tool that enables " \
                            "file access control using a semi capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("--file", "-f", default="")
    parser.add_argument("--grant", "-g", default="READ")
    parser.add_argument("--subject", "-s", default="")
    parser.add_argument("--token", "-t", default="")
    parser.add_argument("--encrypt", "-e", action="store_true")
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "delegate":
        add_or_delegate(args)
    elif args.command == "remove":
        remove(args.file)
    elif args.command == "invoke":
        invoke(args.token)
    elif args.command == "revoke":
        revoke(args.file)
    else:
        print("Command does not exist")

