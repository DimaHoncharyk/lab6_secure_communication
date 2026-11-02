from common.aes_service import AesService
aes = AesService()
aes_key = aes.generate_secret_key()

print("AES key:", aes_key["key"])
print("AES IV:", aes_key["iv"])

message = "Hello! Secure communication Lab 6"
print("Original:", message)

encrypted = aes.encrypt(aes_key, message)
print("Encrypted:", encrypted)

decrypted = aes.decrypt(aes_key, encrypted)
print("Decrypted:", decrypted)

assert message == decrypted
print("AES encryption/decryption successful!")
