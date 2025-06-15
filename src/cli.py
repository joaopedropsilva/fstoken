from argparse import ArgumentParser, Namespace
from pathlib import Path

from daemon import Client
from operation import OperationRegistry, Delete
from helpers import log, log_err


def _try_resolve_file(file: str) -> str:
    try:
        return str(Path(file).resolve(strict=True))
    except OSError:
        return ""


def handle_call(args: Namespace) -> None:
    file = _try_resolve_file(args.file)
    if not file:
        log_err(f"File {args.file} could not be found!")
        exit(1)
    args.file = file

    op = OperationRegistry.get_operation_by_args(args)

    if isinstance(op, Delete):
        call_result = Client.call_daemon(op)
        log_err(call_result.err)
        log(call_result.payload)

        op_unpriv_err = op.run_unpriviledged()
        log_err(op_unpriv_err)
        exit(0)

    op_unpriv_err = op.run_unpriviledged()
    log_err(op_unpriv_err)

    call_result = Client.call_daemon(op)
    log_err(call_result.err)
    log(call_result.payload)


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

