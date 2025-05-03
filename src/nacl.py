from pathlib import Path
from enum import Enum
from pickle import dumps, loads
from nacl.signing import SigningKey, VerifyKey
from nacl.secret import SecretBox
from nacl.public import PrivateKey
from nacl.utils import random
from nacl.encoding import Base64Encoder


class Crypto:
    @staticmethod
    def x25519_keygen(use_b64encoding: bool = False) -> tuple[bytes, bytes]:
        key = PrivateKey.generate()
        private = bytes(key)
        public = bytes(key.public_key)

        if not use_b64encoding:
            return private, public

        return Base64Encoder.encode(private), Base64Encoder.encode(public)

    def encrypt(file_path: Path) -> None:
        key = random(SecretBox.KEY_SIZE)

        encoded_key = Base64Encoder.encode(key).decode("utf-8")
        print("WARNING! THIS IS AN AUTO GENERATED KEY AND YOU WILL\n" \
              "NOT BE ABLE TO RECOVER THE FILE CONTENTS WITHOUT IT\n" \
              "PLEASE KEEP THIS KEY IN A SAFE SPACE.")
        print(f"Generated key result: {encoded_key}")

        box = SecretBox(key)
        with open(file_path, "r+b") as file:
            content = file.read()
            file.seek(0)
            file.truncate(0)

            encrypted = box.encrypt(content)
            file.write(encrypted)

        print("Encryption sucessfully finished! ")

    def decrypt(file_path: Path, key: str) -> None:
        decoded_key = Base64Encoder.decode(key)

        box = SecretBox(decoded_key)
        with open(file_path, "r+b") as file:
            content = file.read()
            file.seek(0)
            file.truncate(0)

            decrypted = box.decrypt(content)
            file.write(decrypted)

        print("Decryption sucessfully finished! ")


class Token:
    @staticmethod
    def get_utf8_str_from_b64(data: bytes) -> str:
        return Base64Encoder.encode(data).decode("utf-8")

    @staticmethod
    def _build_payload(payload: dict, encrypt_payload: bool) -> bytes:
        as_bytes = dumps(payload)

        if not encrypt_payload:
            return as_bytes

        # implement encryption here
        return as_bytes

    def __init__(self,
                 iss_seed: bytes,
                 subject: str,
                 payload: dict,
                 encrypt_payload: bool = False):
        self._signing_key = SigningKey(iss_seed)
        self._verify_key = self._signing_key.verify_key
        self._subject = subject
        self._payload = self._build_payload(payload, encrypt_payload)

    def _sign(self) -> tuple[bytes, bytes]:
        signed_payload = self._signing_key.sign(self._payload)
        return signed_payload.message, signed_payload.signature

    def encode(self) -> str:
        (message, sig) = self._sign()

        public_key = self.get_utf8_str_from_b64(bytes(self._verify_key))
        payload = self.get_utf8_str_from_b64(message)
        signature = self.get_utf8_str_from_b64(sig)

        return f"{public_key}.{payload}.{signature}"

    @staticmethod
    def decode(token: str):
        parts = token.split(".")
        if len(parts) != 3:
            return ""

        public_key = Base64Encoder.decode(parts[0])
        payload = Base64Encoder.decode(parts[1])
        signature = Base64Encoder.decode(parts[2])

        verify_key = VerifyKey(public_key)
        # implement try catch here
        _ = verify_key.verify(payload, signature)

        return public_key, loads(payload), signature

