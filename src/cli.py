from argparse import ArgumentParser, Namespace
from pathlib import Path

from src.keystore import Keystore
from src.fskeys import Fskeys
from src.token import Token
from src.file import File


def handle_call(args: Namespace) -> None:
    is_deletion = args.delete
    is_delegation = args.grant and args.subject
    is_invocation = args.token and not is_delegation

    if is_deletion:
        File.revoke_fstoken_access(args.file)
    if not is_invocation:
        File.grant_fstoken_access(args.file)

    Keystore.change(args)


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
    parser.add_argument("--grant", "-g", default="")
    parser.add_argument("--subject", "-s", default="")
    parser.add_argument("--token", "-t", default="")
    args = parser.parse_args()

    handle_call(args)

