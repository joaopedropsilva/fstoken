from argparse import ArgumentParser, Namespace
from pathlib import Path

from src.fskeys import Fskeys
from src.file import File
from src.daemon import Client


def handle_call(args: Namespace) -> None:
    operation = "addition"
    is_deletion = args.delete
    is_delegation = args.grant and args.subject
    if is_deletion:
        operation = "deletion"
    is_invocation = args.token and not is_delegation
    if is_invocation:
        operation = "invocation"

    if is_deletion:
        pass
        #File.revoke_fstoken_access(args.file)
    if not is_invocation:
        pass
        #File.grant_fstoken_access(args.file)

    Client.call_daemon(operation, args)


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

