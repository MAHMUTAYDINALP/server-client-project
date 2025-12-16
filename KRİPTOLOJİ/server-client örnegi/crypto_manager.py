import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()

    # --- 1. AES (Advanced Encryption Standard) ---
    def aes_encrypt(self, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def aes_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    # --- 2. DES (Data Encryption Standard) ---
    def des_encrypt(self, plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        return encryptor.update(padded_data) + encryptor.finalize()

    def des_decrypt(self, ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    # --- 3. RSA (Rivest–Shamir–Adleman) ---
    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def rsa_encrypt(self, plaintext: bytes, public_key) -> bytes:
        return public_key.encrypt(
            plaintext,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def rsa_decrypt(self, ciphertext: bytes, private_key) -> bytes:
        return private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )