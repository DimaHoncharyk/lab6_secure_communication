import base64

import pytest
from cryptography.exceptions import InvalidTag

from app.rsa_service import RsaService
from common.aes_service import AesService


def test_rsa_key_generation():
    rsa = RsaService()
    keys = rsa.generate_crypto_keys()

    assert "public_key" in keys
    assert "private_key" in keys
    assert keys["public_key"] != keys["private_key"]


def test_rsa_encrypt_decrypt():
    rsa = RsaService()
    keys = rsa.generate_crypto_keys()

    original = "Hello RSA Lab 6!"

    encrypted = rsa.encrypt(
        keys["public_key"], original
    )

    decrypted = rsa.decrypt(
        keys["private_key"], encrypted
    )

    assert decrypted == original
    assert encrypted != original


def test_aes_key_generation():
    aes = AesService()
    keys = aes.generate_secret_key()

    assert len(base64.b64decode(keys["key"])) == 32
    assert len(base64.b64decode(keys["iv"])) == 12


def test_aes_encrypt_decrypt():
    aes = AesService()
    keys = aes.generate_secret_key()

    original = "Secure AES communication!"

    encrypted = aes.encrypt(keys, original)
    decrypted = aes.decrypt(keys, encrypted)

    assert decrypted == original
    assert encrypted != original


def test_aes_invalid_key():
    aes = AesService()

    key1 = aes.generate_secret_key()
    key2 = aes.generate_secret_key()

    encrypted = aes.encrypt(key1, "Secret message")

    with pytest.raises(InvalidTag):
        aes.decrypt(key2, encrypted)
