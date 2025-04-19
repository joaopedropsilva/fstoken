from argparse import ArgumentParser, Namespace
from pathlib import Path
from src.management import encrypt


def call_encrypt_routine(parsed_args: Namespace) -> None:
    if parsed_args.file is None:
        print("Please, specify --file or -f with the desired file path for encryption.")
        exit(1)

    file = Path(parsed_args.file)
    if not file.exists():
        print(f"File {str(file)} not found!")
        exit(1)

    encrypt(file)


if __name__ == "__main__":
    parser = ArgumentParser(prog="fsktoken",
                            description="A command line tool that enables " \
                            "file access control using object capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("--file", "-f")
    args = parser.parse_args()

    if args.command == "enc":
        call_encrypt_routine(args)
    else:
        print("Command does not exist")

