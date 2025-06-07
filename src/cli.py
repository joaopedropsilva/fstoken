from argparse import ArgumentParser, Namespace

from src.daemon import Client
from src.operation import OperationRegistry
from src.helpers import log_err


def handle_call(args: Namespace) -> None:
    op = OperationRegistry.get_operation_by_args(args)

    op.run_unpriviledged()

    Client.call_daemon(op)


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

