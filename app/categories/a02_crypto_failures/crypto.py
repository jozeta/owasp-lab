from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_KEY = b"0123456789abcdef"  # 16 bytes -- hardcoded on purpose, this IS the vulnerability


def encrypt_ecb(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    return cipher.encrypt(padded).hex()


def decrypt_ecb(ciphertext_hex):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    padded = cipher.decrypt(bytes.fromhex(ciphertext_hex))
    return unpad(padded, AES.block_size).decode()
