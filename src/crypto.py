from nacl.signing import SigningKey, VerifyKey
from nacl.public import PrivateKey
from nacl.encoding import Base64Encoder
from nacl.exceptions import BadSignatureError
from nacl.hash import sha256
from nacl.secret import SecretBox
from nacl.utils import random


class NaclBinder:
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
    def sha256_hash(message: bytes) -> bytes:
        hashed = sha256(message)
        return Base64Encoder.encode(hashed)

    @staticmethod
    def secretbox_keygen() -> bytes:
        key = random(SecretBox.KEY_SIZE)
        return Base64Encoder.encode(key)

    @staticmethod
    def secretbox_encrypt(b64key: bytes, raw: bytes) -> bytes:
        box = SecretBox(b64key, encoder=Base64Encoder)
        return box.encrypt(raw)

    @staticmethod
    def secretbox_decrypt(b64key: bytes, encrypted: bytes) -> bytes:
        box = SecretBox(b64key, encoder=Base64Encoder)
        return box.decrypt(encrypted)

