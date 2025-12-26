import socket
import threading
import json
import os
import datetime
from crypto_manager import CryptoManager
from manual_des import ManualDES
from manual_aes import ManualAES
from cryptography.hazmat.primitives import serialization

HOST = '127.0.0.1' 
PORT = 12345

# --- GLOBAL SAYAÇ (Client 1, Client 2... için) ---
CLIENT_ID_COUNTER = 0
COUNTER_LOCK = threading.Lock() # Çakışmayı önlemek için kilit

crypto = CryptoManager()
manual_des = ManualDES()
manual_aes = ManualAES()

aes_iv = b'1234567890123456'
des_iv = b'12345678'

if not os.path.exists("gelen_dosyalar"): os.makedirs("gelen_dosyalar")
CONNECTED_CLIENTS = {}

def log_activity(sender, action, details):
    time_str = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{time_str}] {sender}: {action} -> {details}")

def broadcast_message(content, sender_name, sender_addr, msg_type='MSG', filename=""):
    """
    Mesajı gönderirken artık IP yerine 'Client X' ismini kullanıyoruz.
    """
    print(f"\n[DAĞITIM] Kaynak: {sender_name}")
    
    for target_addr, client_data in CONNECTED_CLIENTS.items():
        if target_addr == sender_addr: continue
        try:
            target_socket = client_data['socket']
            target_params = client_data['params']
            target_algo = client_data['algo']
            target_cat = client_data['category']
            
            encrypted_bytes = b""
            payload_bytes = content if isinstance(content, bytes) else content.encode('utf-8')

            # Şifreleme İşlemi
            if target_cat == 'BLOK':
                if target_algo == 'AES': encrypted_bytes = crypto.aes_encrypt(payload_bytes, target_params['key'], aes_iv)
                elif target_algo == 'DES': encrypted_bytes = crypto.des_encrypt(payload_bytes, target_params['key'], des_iv)
                elif target_algo == 'MANUAL_DES': encrypted_bytes = manual_des.encrypt(payload_bytes, target_params['key'])
                elif target_algo == 'MANUAL_AES': encrypted_bytes = manual_aes.encrypt(payload_bytes, target_params['key'])
                elif target_algo == 'HILL': encrypted_bytes = crypto.hill_encrypt(payload_bytes.decode('utf-8', errors='ignore'), target_params['key']).encode('utf-8')
            
            elif target_cat == 'KLASIK':
                text_msg = payload_bytes.decode('utf-8', errors='ignore')
                if target_algo == 'SEZAR': encrypted_bytes = crypto.caesar_encrypt(text_msg, target_params['key'])
                elif target_algo == 'VIGENERE': encrypted_bytes = crypto.vigenere_encrypt(text_msg, target_params['key'])
                if isinstance(encrypted_bytes, str): encrypted_bytes = encrypted_bytes.encode('utf-8')

            # Pakete 'Client 1' gibi temiz ismi koyuyoruz
            packet = {
                "type": msg_type, 
                "data": encrypted_bytes.hex(), 
                "sender": sender_name,  # <--- BURASI DÜZELDİ
                "filename": filename
            }
            target_socket.send(json.dumps(packet).encode('utf-8'))
            
        except Exception as e: print(f"Dağıtım Hatası ({target_addr}): {e}")

def handle_client(client_socket, addr):
    global CLIENT_ID_COUNTER
    
    # --- OTOMATİK İSİM ATAMA ---
    with COUNTER_LOCK:
        CLIENT_ID_COUNTER += 1
        my_id = CLIENT_ID_COUNTER
    
    client_name = f"Client {my_id}" # Örn: Client 1
    
    log_activity(client_name, "BAĞLANDI", f"IP: {addr[0]}")
    
    try:
        # 1. HANDSHAKE
        srv_rsa_priv, srv_rsa_pub = crypto.generate_rsa_keys()
        srv_ecc_priv, srv_ecc_pub = crypto.generate_ecc_keys()
        
        offer = {
            "rsa_pub": srv_rsa_pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'),
            "ecc_pub": srv_ecc_pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8'),
            "assigned_name": client_name # İstemciye adını bildiriyoruz
        }
        client_socket.send(json.dumps(offer).encode('utf-8'))

        # 2. SEÇİMLERİ AL
        resp = json.loads(client_socket.recv(4096).decode('utf-8'))
        dist = resp['dist_method']
        algo = resp['algo']
        category = resp.get('category', 'BLOK')
        
        session_key = None
        params = {}
        
        if category == 'BLOK':
            if dist == 'RSA':
                session_key = crypto.rsa_decrypt(bytes.fromhex(resp['enc_session_key']), srv_rsa_priv)
            elif dist == 'ECC':
                cli_ecc = serialization.load_pem_public_key(resp['client_ecc_pub'].encode('utf-8'), backend=crypto.backend)
                session_key = crypto.derive_shared_secret(srv_ecc_priv, cli_ecc)
            
            if algo in ['AES', 'MANUAL_AES']: session_key = session_key[:16]
            elif algo == 'DES': session_key = session_key[:24]
            elif algo == 'MANUAL_DES': session_key = session_key[:8]
            
            params['key'] = session_key
            if algo == 'HILL': params['key'] = [3,3,2,5]

        elif category == 'KLASIK':
            params = resp['params']

        CONNECTED_CLIENTS[addr] = {'socket': client_socket, 'params': params, 'algo': algo, 'category': category}
        print(f"[KURULUM] {client_name} -> {algo} ({dist})")

        # 3. İLETİŞİM
        while True:
            raw = client_socket.recv(5*1024*1024)
            if not raw: break
            try:
                pkt = json.loads(raw.decode('utf-8'))
                enc_bytes = bytes.fromhex(pkt['data'])
                decrypted = None
                
                # Çözme
                if category == 'BLOK':
                    if algo == 'AES': decrypted = crypto.aes_decrypt(enc_bytes, params['key'], aes_iv)
                    elif algo == 'DES': decrypted = crypto.des_decrypt(enc_bytes, params['key'], des_iv)
                    elif algo == 'MANUAL_DES': decrypted = manual_des.decrypt(enc_bytes, params['key'])
                    elif algo == 'MANUAL_AES': decrypted = manual_aes.decrypt(enc_bytes, params['key'])
                    elif algo == 'HILL': decrypted = crypto.hill_decrypt(enc_bytes.decode('utf-8', errors='ignore'), params['key']).encode('utf-8')
                elif category == 'KLASIK':
                    t = enc_bytes.decode('utf-8', errors='ignore')
                    if algo == 'SEZAR': decrypted = crypto.caesar_decrypt(t, params['key'])
                    elif algo == 'VIGENERE': decrypted = crypto.vigenere_decrypt(t, params['key'])

                # Güvenli Decode (Çökme Önleyici)
                if isinstance(decrypted, bytes):
                    msg_text = decrypted.decode('utf-8', errors='replace') 
                else:
                    msg_text = str(decrypted)

                if pkt['type'] == 'MSG':
                    print(f"💬 {client_name}: {msg_text}")
                    broadcast_message(decrypted, client_name, addr, 'MSG')
                    
                elif pkt['type'] == 'FILE':
                    fname = pkt.get('filename')
                    # Klasör adı artık 'gelen_dosyalar/Client 1' olacak
                    u_dir = os.path.join("gelen_dosyalar", client_name)
                    if not os.path.exists(u_dir): os.makedirs(u_dir)
                    
                    save_path = os.path.join(u_dir, fname)
                    with open(save_path, "wb") as f: f.write(decrypted)
                    
                    log_activity(client_name, "DOSYA", f"{fname} kaydedildi.")
                    broadcast_message(decrypted, client_name, addr, 'FILE', fname)

            except Exception as e: print(f"Paket Hatası: {e}")

    except Exception as e: log_activity(client_name, "HATA", str(e))
    finally:
        if addr in CONNECTED_CLIENTS: del CONNECTED_CLIENTS[addr]
        client_socket.close()

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[SERVER] Korumalı Mod Aktif (Sıralı İsimlendirme)")
    while True:
        c, a = s.accept()
        threading.Thread(target=handle_client, args=(c, a)).start()

if __name__ == "__main__":
    start_server()