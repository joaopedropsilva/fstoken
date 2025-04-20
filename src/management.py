from nacl import secret, utils
from base64 import b64encode, b64decode
from pathlib import Path


def encrypt(file_path: Path) -> None:
    key = utils.random(secret.SecretBox.KEY_SIZE)
    encoded_key = b64encode(key).decode("utf-8")
    box = secret.SecretBox(key)

    print("WARNING! THIS IS AN AUTO GENERATED KEY AND YOU WILL\n" \
          "NOT BE ABLE TO RECOVER THE FILE CONTENTS WITHOUT IT\n"
          "PLEASE KEEP THIS KEY IN A SAFE SPACE.")
    print(f"Generated key result: {encoded_key}")

    with open(file_path, "r+b") as file:  # check file acess level
        content = file.read()
        file.seek(0)
        file.truncate(0)

        encrypted = box.encrypt(content)
        file.write(encrypted)

    print("Encryption sucessfully finished! ")


def decrypt(file_path: Path, key: str) -> None:
    decoded_key = b64decode(key)
    box = secret.SecretBox(decoded_key)

    with open(file_path, "r+b") as file:
        content = file.read()
        file.seek(0)
        file.truncate(0)

        decrypted = box.decrypt(content)
        file.write(decrypted)

    print("Decryption sucessfully finished! ")

