from argparse import ArgumentParser

from .core import Fskeys
from .token import Token


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

    file _key = ""

    # Retrieve from cli
    subject = \
        input("Delegate access to: ").strip().lower()
    grant = \
        input("Grant access of [READ | READ/WRITE]: ").strip().lower()

    (private, public) = Fskeys.get_keys()
    token = Token.encode(private, payload={"file": file,
                                           "grant": grant,
                                           "to": subject,
                                           "extra": extra_data})

    print("Token generated:")
    print(f"{token}")


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
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "tokenize":
        tokenize(args.file)
    elif args.command == "decode":
        decode(args.token)
    else:
        print("Command does not exist")

