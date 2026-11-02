import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class RsaService:
    def generate_crypto_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return {
            "public_key": base64.b64encode(public_bytes).decode(),
            "private_key": base64.b64encode(private_bytes).decode()
        }

    def encrypt(self, public_key, plain_text):
        key = serialization.load_der_public_key(
            base64.b64decode(public_key)
        )

        encrypted = key.encrypt(
            plain_text.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return base64.b64encode(encrypted).decode()

    def decrypt(self, private_key, cipher_text):
        key = serialization.load_der_private_key(
            base64.b64decode(private_key),
            password=None
        )

        decrypted = key.decrypt(
            base64.b64decode(cipher_text),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted.decode("utf-8")
