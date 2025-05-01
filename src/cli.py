from argparse import ArgumentParser, Namespace
from pathlib import Path
from src.core import Fskeys


def init() -> None:
    (err, init_successful) = Fskeys.init(verbose=True)
    if not init_successful:
        print(err)
        exit(1)


if __name__ == "__main__":
    parser = ArgumentParser(prog="fsktoken",
                            description="A command line tool that enables " \
                            "file access control using object capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("--file", "-f")
    parser.add_argument("--key", "-k")
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "enc":
        call_encrypt_routine(args)
    elif args.command == "dec":
        call_decrpyt_routine(args)
    else:
        print("Command does not exist")

