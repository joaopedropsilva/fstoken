from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.hash import sha256
from nacl.secret import SecretBox
from nacl.utils import random


class NaclBinder:
    @staticmethod
    def x25519_keygen(use_b64encoding: bool = False) -> tuple[bytes, bytes]:
        key = PrivateKey.generate()
        private = bytes(key)
        public = bytes(key.public_key)

        if not use_b64encoding:
            return private, public

        return Base64Encoder.encode(private), Base64Encoder.encode(public)

    @staticmethod
    def sign_message(seed: bytes, message: bytes) -> tuple[bytes, bytes, bytes]:
        signing_key = SigningKey(seed)
        verify_key = signing_key.verify_key

        signed = signing_key.sign(message)

        return bytes(verify_key), bytes(signed.message), bytes(signed.signature)

    @staticmethod
    def verify_message(public_key: bytes,
                       message: bytes,
                       signature: bytes) -> None:
        verifier = VerifyKey(public_key)
        verifier.verify(message, signature)

    @staticmethod
    def sha256_hash(message: bytes, use_b64encoding: bool = False) -> bytes:
        hashed = sha256(message)
        if not use_b64encoding:
            return hashed

        return Base64Encoder.encode(hashed)

    @staticmethod
    def secretbox_keygen(use_b64encoding: bool = False) -> bytes:
        key = random(SecretBox.KEY_SIZE)
        if not use_b64encoding:
            return key

        return Base64Encoder.encode(key)

    @staticmethod
    def secretbox_encrypt(key: bytes, raw: bytes) -> bytes:
        box = SecretBox(key)
        return box.encrypt(raw)

    @staticmethod
    def secretbox_decrypt(key: bytes, encrypted: bytes) -> bytes:
        box = SecretBox(key)
        return box.decrypt(encrypted)

