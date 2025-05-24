from argparse import ArgumentParser, Namespace
from pathlib import Path

from src.fskeys import Fskeys, Keystore
from src.token import Token
from src.file import File
from src.helpers import log


def _handle_deletion(args: Namespace,
                     was_encrypted: bool,
                     prev_key: str) -> None:
    if prev_key == "":
        log(f"File not found in {Keystore.STORE_FILENAME}", args.verbose)
        exit(1)

    log(f"Removing from {Keystore.STORE_FILENAME}", args.verbose)
    Keystore.change_entry(args.file, delete=True)

    if was_encrypted:
        if not File.decrypt(args.file, prev_key):
            exit(1)

    exit(0)


def _handle_invocation(args: Namespace) -> None:
    pass


def handle_call(args: Namespace) -> None:
    Fskeys.init(verbose=args.verbose)

    (was_encrypted, prev_key) = Keystore.search_entry_state(args.file)

    is_deletion = args.delete
    is_delegation = args.token and args.grant and args.subject
    is_invocation = args.token and not is_delegation

    if is_deletion:
        _handle_deletion(args, was_encrypted, prev_key)
    if is_invocation:
        _handle_invocation(args)

    filekey = Keystore.change_entry(args.file,
                                    encrypt=args.encrypt,
                                    rotate_key=args.rotate,
                                    delete=False)

    if was_encrypted:
        if not File.decrypt(args.file, prev_key):
            exit(1)
    if args.encrypt:
        if not File.encrypt(args.file, filekey):
            exit(1)

    if is_delegation:
        (private, _) = Fskeys.get_keys()
        token = Token.encode(private, raw_payload={"file_key": filekey,
                                                   "grant": args.grant,
                                                   "subject": args.subject,
                                                   "proof": [args.token]})
        print(token)


if __name__ == "__main__":
    parser = ArgumentParser(prog="fstoken",
                            description="A command line tool that enables " \
                            "file access control using a semi capabilities " \
                            "model and encryption.")
    parser.add_argument("file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--encrypt", "-e", action="store_true")
    parser.add_argument("--rotate", "-r", action="store_true")
    parser.add_argument("--delete", "-d", action="store_true")
    parser.add_argument("--grant", "-g", default="READ")
    parser.add_argument("--subject", "-s", default="")
    parser.add_argument("--token", "-t", default="")
    args = parser.parse_args()

    handle_call(args)

