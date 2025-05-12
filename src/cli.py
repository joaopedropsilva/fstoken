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

    # get file_key based on ownership
    # sugest file encryption
    file_key = ""
    # Retrieve from cli
    subject = \
        input("Delegate access to: ").strip().upper()
    grant = \
        input("Grant access of [READ | READ/WRITE]: ").strip().upper()
    delegated_token = ""

    (private, public) = Fskeys.get_keys()
    token = Token.encode(private, raw_payload={"file_key": file,
                                               "grant": grant,
                                               "subject": subject,
                                               "proof": [delegated_token]})

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
                            "file access control using a semi capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("file")
    parser.add_argument("grant", nargs="?", default="READ")
    parser.add_argument("token", nargs="?", default="")
    args = parser.parse_args()

    if args.command == "init":
        init()
    elif args.command == "tokenize":
        tokenize(args.file)
    elif args.command == "decode":
        decode(args.token)
    else:
        print("Command does not exist")

