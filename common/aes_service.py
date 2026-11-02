import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AesService:
    def generate_secret_key(self):
        key = AESGCM.generate_key(bit_length=256)
        iv = os.urandom(12)

        return {
            "key": base64.b64encode(key).decode("utf-8"),
            "iv": base64.b64encode(iv).decode("utf-8")
        }

    def encrypt(self, aes_key, plain_text):
        key = base64.b64decode(aes_key["key"])
        iv = base64.b64decode(aes_key["iv"])

        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(
            iv,
            plain_text.encode("utf-8"),
            None
        )

        return base64.b64encode(encrypted).decode("utf-8")

    def decrypt(self, aes_key, cipher_text):
        key = base64.b64decode(aes_key["key"])
        iv = base64.b64decode(aes_key["iv"])

        aesgcm = AESGCM(key)
        decrypted = aesgcm.decrypt(
            iv,
            base64.b64decode(cipher_text),
            None
        )

        return decrypted.decode("utf-8")
