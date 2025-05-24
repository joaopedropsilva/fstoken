from argparse import ArgumentParser, Namespace
from pathlib import Path

from src.fskeys import Fskeys, Keystore
from src.token import Token
from src.file import File


def _require_init_before_exec() -> None:
    Fskeys.check_dir_and_contents()


def init() -> None:
    Fskeys.init(verbose=True)


def handle_call(args: Namespace) -> None:
    _require_init_before_exec()

    if args.file == "":
        print("A file must be passed to use this command")

    (was_encrypted, prev_key) = Keystore.search_entry_state(args.file)
    if args.delete and prev_key == "":
        return

    filekey = Keystore.change_entry(args.file,
                                    args.encrypt,
                                    args.rotate,
                                    args.delete)

    if was_encrypted:
        File.decrypt(args.file, prev_key)  # Prevents content lost if key rotates
    if args.encrypt:
        File.encrypt(args.file, filekey)

    if args.grant == "" or args.subject == "":
        return

    (private, _) = Fskeys.get_keys()
    token = Token.encode(private, raw_payload={"file_key": filekey,
                                               "grant": args.grant,
                                               "subject": args.subject,
                                               "proof": [args.token]})
    print(token)


def invoke(filestring: str, token: str) -> None:
    # Token eval
    pass


if __name__ == "__main__":
    parser = ArgumentParser(prog="fstoken",
                            description="A command line tool that enables " \
                            "file access control using a semi capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("--file", "-f", default="")
    parser.add_argument("--encrypt", "-e", action="store_true")
    parser.add_argument("--rotate", "-r", action="store_true")
    parser.add_argument("--delete", "-d", action="store_true")
    parser.add_argument("--grant", "-g", default="READ")
    parser.add_argument("--subject", "-s", default="")
    parser.add_argument("--token", "-t", default="")
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "delegate":
        handle_call(args)
    elif args.command == "invoke":
        invoke(args.token)
    else:
        print("Command does not exist")

