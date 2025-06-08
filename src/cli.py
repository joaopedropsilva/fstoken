from argparse import ArgumentParser, Namespace

from src.daemon import Client
from src.operation import OperationRegistry
from src.helpers import log, log_err


def handle_call(args: Namespace) -> None:
    op = OperationRegistry.get_operation_by_args(args)

    op_unpriv_err = op.run_unpriviledged()
    log_err(op_unpriv_err)

    (call_err, call_result) = Client.call_daemon(op)
    log_err(call_err)
    log(call_result)


if __name__ == "__main__":
    parser = ArgumentParser(prog="fstoken",
                            description="A command line tool that enables " \
                            "file access control using a semi capabilities " \
                            "model and encryption.")
    parser.add_argument("file")
    parser.add_argument("--encrypt", "-e", action="store_true")
    parser.add_argument("--rotate", "-r", action="store_true")
    parser.add_argument("--delete", "-d", action="store_true")
    parser.add_argument("--grant", "-g", default="")
    parser.add_argument("--subject", "-s", default="")
    parser.add_argument("--token", "-t", default="")
    args = parser.parse_args()

    handle_call(args)

