import socket
import threading
import os
from crypto_manager import CryptoManager
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1' # Server IP
PORT = 12345

crypto = CryptoManager()
aes_iv = b'1234567890123456'
des_iv = b'12345678'

def receive_messages(sock, key, mode):
    while True:
        try:
            buffer_size = 256 if mode == 'RSA' else 1024
            encrypted_data = sock.recv(buffer_size)
            if not encrypted_data:
                break
            
            msg = ""
            if mode == 'AES':
                msg = crypto.aes_decrypt(encrypted_data, key, aes_iv).decode('utf-8')
            elif mode == 'DES':
                msg = crypto.des_decrypt(encrypted_data, key, des_iv).decode('utf-8')
            elif mode == 'RSA':
                # RSA modunda 'key' bizim Private Key'imizdir
                msg = crypto.rsa_decrypt(encrypted_data, key).decode('utf-8')

            print(f"\n[GELEN ({mode})]: {msg}")
            print("Sen: ", end="", flush=True)
        except:
            print("\n[BİLGİ] Bağlantı koptu.")
            break

def start_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((HOST, PORT))

        # 1. Server'ın Public Key'ini al
        server_pub_bytes = client.recv(1024)
        server_public_key = serialization.load_pem_public_key(server_pub_bytes, backend=crypto.backend)

        # --- KULLANICI SEÇİMİ ---
        print("-" * 40)
        print(" KRİPTOGRAFİ LABORATUVARI ")
        print(" Hangi algoritmayı kullanmak istersiniz?")
        print(" -> AES  (Standart, Hızlı)")
        print(" -> DES  (Eski, Yavaş)")
        print(" -> RSA  (Asimetrik, Çok Yavaş, Mesajlaşma için deneysel)")
        print("-" * 40)
        
        mode = input("Seçiminiz (AES / DES / RSA): ").strip().upper()
        if mode not in ['AES', 'DES', 'RSA']:
            print("Hatalı seçim! AES varsayılıyor.")
            mode = 'AES'

        # 2. Seçilen modu Server'a bildir
        client.send(mode.encode('utf-8'))

        # 3. Anahtar Yönetimi
        key_for_listening = None # Thread'e göndereceğimiz anahtar
        
        if mode == 'RSA':
            # RSA Modu: Kendi anahtarlarımızı üretip Public olanı Server'a atıyoruz
            print("[RSA] Kendi anahtar çiftimiz üretiliyor...")
            my_private_key, my_public_key = crypto.generate_rsa_keys()
            
            my_pub_bytes = my_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client.send(my_pub_bytes)
            print("[RSA] Public Key Server'a gönderildi.")
            key_for_listening = my_private_key # Dinlerken kendi Private Key'imizi kullanacağız

        else: # AES veya DES
            session_key = b''
            if mode == 'AES':
                session_key = os.urandom(32)
            elif mode == 'DES':
                session_key = os.urandom(24)
            
            # Anahtarı Server'ın kilidiyle şifrele gönder
            encrypted_key = crypto.rsa_encrypt(session_key, server_public_key)
            client.send(encrypted_key)
            print(f"[{mode}] Session Key üretildi ve güvenle gönderildi.")
            key_for_listening = session_key

        print("-" * 40)
        
        # Dinleme Thread'i
        thread = threading.Thread(target=receive_messages, args=(client, key_for_listening, mode))
        thread.daemon = True
        thread.start()

        # Gönderme Döngüsü
        while True:
            msg = input("Sen: ")
            if msg.lower() == 'q':
                break
            
            encrypted_msg = b""
            if mode == 'AES':
                encrypted_msg = crypto.aes_encrypt(msg.encode('utf-8'), session_key, aes_iv)
            elif mode == 'DES':
                encrypted_msg = crypto.des_encrypt(msg.encode('utf-8'), session_key, des_iv)
            elif mode == 'RSA':
                # RSA ile gönderirken Server'ın Public Key'ini kullanırız
                if len(msg) > 190: 
                    print("UYARI: RSA sınırı aşıldı, mesaj kırpılıyor.")
                    msg = msg[:190]
                encrypted_msg = crypto.rsa_encrypt(msg.encode('utf-8'), server_public_key)
                
            client.send(encrypted_msg)

    except Exception as e:
        print(f"[HATA] {e}")
    finally:
        client.close()

if __name__ == "__main__":
    start_client()