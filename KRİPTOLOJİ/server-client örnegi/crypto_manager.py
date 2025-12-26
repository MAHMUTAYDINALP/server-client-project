from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding as asym_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import os
import string

class CryptoManager:
    def __init__(self):
        self.backend = default_backend()
        self.alphabet = string.ascii_lowercase

    # --- 1. KLASİK ŞİFRELEME ---
    def caesar_encrypt(self, text, shift):
        result = ""
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                result += chr((ord(char) - start + shift) % 26 + start)
            else: result += char
        return result.encode('utf-8')

    def caesar_decrypt(self, text, shift):
        return self.caesar_encrypt(text, -shift).decode('utf-8')

    def vigenere_encrypt(self, text, key):
        result = []
        key_index = 0
        key = key.lower()
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('a')
                start = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - start + shift) % 26 + start))
                key_index += 1
            else: result.append(char)
        return "".join(result).encode('utf-8')

    def vigenere_decrypt(self, text, key):
        result = []
        key_index = 0
        key = key.lower()
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord('a')
                start = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - start - shift) % 26 + start))
                key_index += 1
            else: result.append(char)
        return "".join(result)

    def substitution_encrypt(self, text, key_map):
        table = str.maketrans(string.ascii_lowercase + string.ascii_uppercase, key_map.lower() + key_map.upper())
        return text.translate(table).encode('utf-8')

    def substitution_decrypt(self, text, key_map):
        table = str.maketrans(key_map.lower() + key_map.upper(), string.ascii_lowercase + string.ascii_uppercase)
        return text.translate(table)

    def affine_encrypt(self, text, a, b):
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                x = ord(char.lower()) - ord('a')
                result += chr(((a * x + b) % 26) + ord('A' if is_upper else 'a'))
            else: result += char
        return result.encode('utf-8')

    def affine_decrypt(self, text, a, b):
        try:
            a_inv = pow(a, -1, 26)
        except ValueError:
            return "HATA: 'a' sayısının tersi yok (asal değil)."
            
        result = ""
        for char in text:
            if char.isalpha():
                is_upper = char.isupper()
                y = ord(char.lower()) - ord('a')
                result += chr(((a_inv * (y - b)) % 26) + ord('A' if is_upper else 'a'))
            else: result += char
        return result

    # --- 2. BLOK ŞİFRELEME ---
    def hill_encrypt(self, text, key_matrix):
        # Basit Hill Cipher (2x2 matris varsayımıyla)
        text = text.upper().replace(" ", "")
        if len(text) % 2 != 0: text += "X"
        result = ""
        for i in range(0, len(text), 2):
            p1 = ord(text[i]) - 65
            p2 = ord(text[i+1]) - 65
            c1 = (key_matrix[0] * p1 + key_matrix[1] * p2) % 26
            c2 = (key_matrix[2] * p1 + key_matrix[3] * p2) % 26
            result += chr(c1 + 65) + chr(c2 + 65)
        return result

    def hill_decrypt(self, text, key_matrix):
        det = (key_matrix[0] * key_matrix[3] - key_matrix[1] * key_matrix[2]) % 26
        try:
            det_inv = pow(det, -1, 26)
        except ValueError:
            return "HATA: Matrisin tersi yok."
            
        inv_matrix = [
            (key_matrix[3] * det_inv) % 26, 
            (-key_matrix[1] * det_inv) % 26, 
            (-key_matrix[2] * det_inv) % 26, 
            (key_matrix[0] * det_inv) % 26
        ]
        return self.hill_encrypt(text, inv_matrix)

    def aes_encrypt(self, plaintext, key, iv):
        if len(key) > 16: key = key[:16]
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def aes_decrypt(self, ciphertext, key, iv):
        if len(key) > 16: key = key[:16]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    def des_encrypt(self, plaintext, key, iv):
        # Triple DES için 16 veya 24 byte anahtar gerekir, değilse tamamla/kırp
        while len(key) < 24: key += b'0'
        if len(key) > 24: key = key[:24]
            
        padder = padding.PKCS7(64).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        return encryptor.update(padded_data) + encryptor.finalize()

    def des_decrypt(self, ciphertext, key, iv):
        while len(key) < 24: key += b'0'
        if len(key) > 24: key = key[:24]
            
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(64).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

    # --- 3. ASİMETRİK ŞİFRELEME (RSA & ECC) - EKSİK OLAN KISIM BURASIYDI ---
    
    # A. RSA YÖNTEMİ
    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=self.backend)
        return private_key, private_key.public_key()

    def rsa_encrypt(self, plaintext, public_key):
        return public_key.encrypt(
            plaintext,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    def rsa_decrypt(self, ciphertext, private_key):
        return private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )

    # B. ECC (ELİPTİK EĞRİ) YÖNTEMİ
    def generate_ecc_keys(self):
        # SECP256R1 eğrisi (Bitcoin ve HTTPS'in standardı)
        private_key = ec.generate_private_key(ec.SECP256R1(), self.backend)
        return private_key, private_key.public_key()
    
    def derive_shared_secret(self, private_key, peer_public_key):
        """
        ECDH: Kendi Private Key'im + Karşı tarafın Public Key'i = ORTAK SIR
        """
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Elde edilen ham sırrı AES anahtarına çevir (HKDF)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=self.backend
        ).derive(shared_key)
        
        return derived_key