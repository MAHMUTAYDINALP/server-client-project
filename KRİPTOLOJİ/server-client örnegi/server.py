import socket
import threading
from crypto_manager import CryptoManager
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1' # Kendi IP adresini yazabilirsin
PORT = 12345

crypto = CryptoManager()
aes_iv = b'1234567890123456'
des_iv = b'12345678'

# RSA Modunda Server'ın mesaj atabilmesi için Client'ın kilidine ihtiyacı var
client_public_key = None 

def receive_messages(client_socket, key, mode):
    while True:
        try:
            # RSA şifreli mesajlar 256 byte gelir (2048 bit anahtar için)
            buffer_size = 256 if mode == 'RSA' else 1024
            encrypted_data = client_socket.recv(buffer_size)
            if not encrypted_data:
                break
            
            msg = ""
            if mode == 'AES':
                msg = crypto.aes_decrypt(encrypted_data, key, aes_iv).decode('utf-8')
            elif mode == 'DES':
                msg = crypto.des_decrypt(encrypted_data, key, des_iv).decode('utf-8')
            elif mode == 'RSA':
                # RSA modunda 'key' parametresi aslında bizim Private Key'imizdir
                msg = crypto.rsa_decrypt(encrypted_data, key).decode('utf-8')
            
            print(f"\n[GELEN ({mode})]: {msg}")
            print("Sen: ", end="", flush=True)
        except Exception as e:
            # print(f"Hata: {e}")
            break

def start_server():
    global client_public_key
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    
    print(f"[SERVER] {HOST}:{PORT} - Hazır. Bağlantı bekleniyor...")
    
    # 1. Server kendi RSA Kimliğini oluşturur
    server_private_key, server_public_key = crypto.generate_rsa_keys()
    
    client_socket, addr = server.accept()
    print(f"[BAĞLANTI] {addr} geldi.")

    # 2. Server kendi Public Key'ini gönderir
    pub_key_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(pub_key_bytes)

    # 3. MOD SEÇİMİNİ AL ("AES", "DES" veya "RSA")
    mode_data = client_socket.recv(1024).decode('utf-8').upper()
    print(f"[SEÇİM] Kullanıcı modu: {mode_data}")

    # 4. MODA GÖRE ANAHTAR DEĞİŞİMİ
    session_key_or_private = None

    if mode_data == 'RSA':
        print("[BİLGİ] RSA Modu: Client'ın Public Key'i bekleniyor...")
        client_pub_bytes = client_socket.recv(1024)
        client_public_key = serialization.load_pem_public_key(
            client_pub_bytes, backend=crypto.backend
        )
        print("[BAŞARILI] Client Public Key alındı.")
        session_key_or_private = server_private_key # Mesajları çözmek için kendi özel anahtarımızı kullanacağız

    else: # AES veya DES
        print(f"[BİLGİ] {mode_data} için Session Key bekleniyor...")
        encrypted_session_key = client_socket.recv(256)
        session_key_or_private = crypto.rsa_decrypt(encrypted_session_key, server_private_key)
        print(f"[BAŞARILI] {mode_data} Anahtarı alındı.")

    print("-" * 40)

    # Dinleme thread'i başlat
    thread = threading.Thread(target=receive_messages, args=(client_socket, session_key_or_private, mode_data))
    thread.start()

    while True:
        msg = input("Sen: ")
        if msg.lower() == 'q':
            break
        
        # Gönderim Mantığı
        try:
            encrypted_msg = b""
            if mode_data == 'AES':
                encrypted_msg = crypto.aes_encrypt(msg.encode('utf-8'), session_key_or_private, aes_iv)
            elif mode_data == 'DES':
                encrypted_msg = crypto.des_encrypt(msg.encode('utf-8'), session_key_or_private, des_iv)
            elif mode_data == 'RSA':
                # RSA'da karşı tarafın (Client'ın) kilidiyle kilitleriz
                if len(msg) > 190: # RSA sınır uyarısı
                    print("UYARI: RSA ile çok uzun mesaj atamazsın! Mesaj kısaltıldı.")
                    msg = msg[:190]
                encrypted_msg = crypto.rsa_encrypt(msg.encode('utf-8'), client_public_key)
                
            client_socket.send(encrypted_msg)
        except Exception as e:
            print(f"Gönderim Hatası: {e}")

    client_socket.close()

if __name__ == "__main__":
    start_server()