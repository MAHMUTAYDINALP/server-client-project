import os
# Buraya dikkat: utils klasörünün içindeki crypto_manager dosyasından CryptoManager sınıfını çekiyoruz
from utils.crypto_manager import CryptoManager

def main():
    # Sınıfı başlatıyoruz
    crypto = CryptoManager()
    
    # Şifrelenecek verimiz (byte formatında olmalı, o yüzden başına b koyuyoruz)
    mesaj = b"Bu cok gizli bir HR verisidir: Maaslar yukseldi!"
    print(f"Orijinal Mesaj: {mesaj}\n" + "-"*50)

    # --- 1. AES TEST ---
    print(">>> AES TESTI BASLIYOR...")
    aes_key = os.urandom(32) # 32 byte anahtar
    aes_iv = os.urandom(16)  # 16 byte IV
    
    aes_sifreli = crypto.aes_encrypt(mesaj, aes_key, aes_iv)
    aes_cozulmus = crypto.aes_decrypt(aes_sifreli, aes_key, aes_iv)
    
    print(f"[AES] Sifreli Veri: {aes_sifreli.hex()[:30]}...") 
    print(f"[AES] Cozulmus Veri: {aes_cozulmus.decode('utf-8')}")
    print("-" * 50)

    # --- 2. DES TEST ---
    print(">>> DES TESTI BASLIYOR...")
    des_key = os.urandom(24) 
    des_iv = os.urandom(8)
    
    des_sifreli = crypto.des_encrypt(mesaj, des_key, des_iv)
    des_cozulmus = crypto.des_decrypt(des_sifreli, des_key, des_iv)
    
    print(f"[DES] Sifreli Veri: {des_sifreli.hex()[:30]}...")
    print(f"[DES] Cozulmus Veri: {des_cozulmus.decode('utf-8')}")
    print("-" * 50)

    # --- 3. RSA TEST ---
    print(">>> RSA TESTI BASLIYOR...")
    private_key, public_key = crypto.generate_rsa_keys()
    
    rsa_sifreli = crypto.rsa_encrypt(mesaj, public_key)
    rsa_cozulmus = crypto.rsa_decrypt(rsa_sifreli, private_key)
    
    print(f"[RSA] Sifreli Veri (Uzunluk {len(rsa_sifreli)}): {rsa_sifreli.hex()[:30]}...")
    print(f"[RSA] Cozulmus Veri: {rsa_cozulmus.decode('utf-8')}")
    print("-" * 50)

if __name__ == "__main__":
    main()