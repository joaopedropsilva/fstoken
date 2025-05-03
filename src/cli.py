from argparse import ArgumentParser, Namespace
from pathlib import Path
from src.core import Fskeys
from src.nacl import Token

def _require_init_before_exec() -> None:
    check_result = Fskeys.check_dir_and_contents()
    if check_result != "":
        print(check_result)
        print("fstoken must be initialized "
              "with fstoken init before usage!")
        exit(1)

def init() -> None:
    Fskeys.init(verbose=True)

def tokenize(file: str, extra: str) -> None:
    _require_init_before_exec()

    if file == "":
        print("A file must be passed to generate a token!")
        exit(1)
    from json import load
    extra_data = {}
    if extra != "":
        extra_data = load(extra)

    subject = \
        input("Delegate access to: ").strip().lower()

    grant = \
        input("Grant access of [READ | READ/WRITE]: ").strip().lower()

    (private, public) = Fskeys.get_keys()
    token = Token(iss_seed=private,
                  subject=subject,
                  payload={"file": file, "grant": grant, "extra": extra_data})

    print("Token generated:")
    print(f"{token.encode()}")


def decode(token: str) -> None:
    if token == "":
        print("A token is required for this operation!")

    (_, p, _) = Token.decode(token)
    print(p)


if __name__ == "__main__":
    parser = ArgumentParser(prog="fsktoken",
                            description="A command line tool that enables " \
                            "file access control using object capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("token", nargs="?", default="")
    parser.add_argument("--file", "-f", default="")
    parser.add_argument("--extra", "-e", default="")
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "tokenize":
        tokenize(args.file, args.extra)
    elif args.command == "decode":
        decode(args.token)
    else:
        print("Command does not exist")

