from argparse import ArgumentParser, Namespace
from pathlib import Path
from src.management import encrypt, decrypt


def call_encrypt_routine(parsed_args: Namespace) -> None:
    file = parsed_args.file
    if file is None:
        print("Please, specify --file or -f with the desired file path for " \
              "encryption.")
        exit(1)
    file = Path(file)
    if not file.exists():
        print(f"File {str(file)} not found!")
        exit(1)

    encrypt(file)

def call_decrpyt_routine(parsed_args: Namespace) -> None:
    file = parsed_args.file
    if file is None:
        print("Please, specify --file or -f with the desired file path for " \
              "decryption.")
        exit(1)
    file = Path(file)
    if not file.exists():
        print(f"File {str(file)} not found!")
        exit(1)
    key = parsed_args.key
    if key is None:
        print("Please, specify --key or -k with the key for decryption.")
        exit(1)
    key = key.strip()

    decrypt(file, key)


if __name__ == "__main__":
    parser = ArgumentParser(prog="fsktoken",
                            description="A command line tool that enables " \
                            "file access control using object capabilities " \
                            "model and encryption.")
    parser.add_argument("command")
    parser.add_argument("--file", "-f")
    parser.add_argument("--key", "-k")
    args = parser.parse_args()

    if args.command == "enc":
        call_encrypt_routine(args)
    elif args.command == "dec":
        call_decrpyt_routine(args)
    else:
        print("Command does not exist")

