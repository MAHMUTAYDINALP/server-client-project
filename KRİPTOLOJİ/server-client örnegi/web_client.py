import streamlit as st # type: ignore
import socket
import threading
import json
import os
import time
import queue
import string, random
from crypto_manager import CryptoManager
from manual_des import ManualDES
from manual_aes import ManualAES
from cryptography.hazmat.primitives import serialization

st.set_page_config(page_title="Kripto İstasyonu", page_icon="🛡️", layout="wide")

# State
if 'socket' not in st.session_state: st.session_state.socket = None
if 'messages' not in st.session_state: st.session_state.messages = []
if 'connected' not in st.session_state: st.session_state.connected = False
if 'my_name' not in st.session_state: st.session_state.my_name = "Bilinmiyor"
if 'crypto' not in st.session_state: st.session_state.crypto = CryptoManager()
if 'manual_des' not in st.session_state: st.session_state.manual_des = ManualDES()
if 'manual_aes' not in st.session_state: st.session_state.manual_aes = ManualAES()
if 'data_queue' not in st.session_state: st.session_state.data_queue = queue.Queue()
if 'params' not in st.session_state: st.session_state.params = {}
if 'algo' not in st.session_state: st.session_state.algo = "AES"

AES_IV = b'1234567890123456'
DES_IV = b'12345678'

def encrypt_data_safe(data, cat, algo, params, c_lib, m_des, m_aes):
    if cat == 'KLASIK':
        t = data if isinstance(data, str) else data.decode('utf-8')
        if algo == 'SEZAR': return c_lib.caesar_encrypt(t, params['key'])
        elif algo == 'VIGENERE': return c_lib.vigenere_encrypt(t, params['key'])
        return data.encode('utf-8')

    b_data = data if isinstance(data, bytes) else data.encode('utf-8')
    if algo == 'AES': return c_lib.aes_encrypt(b_data, params['key'], AES_IV)
    elif algo == 'DES': return c_lib.des_encrypt(b_data, params['key'], DES_IV)
    elif algo == 'MANUAL_DES': return m_des.encrypt(b_data, params['key'])
    elif algo == 'MANUAL_AES': return m_aes.encrypt(b_data, params['key'])
    elif algo == 'HILL': return c_lib.hill_encrypt(b_data.decode('utf-8'), params['key']).encode('utf-8')
    return b_data

def decrypt_data_safe(enc_bytes, cat, algo, params, c_lib, m_des, m_aes):
    try:
        if cat == 'KLASIK':
            t = enc_bytes.decode('utf-8')
            if algo == 'SEZAR': return c_lib.caesar_decrypt(t, params['key'])
            elif algo == 'VIGENERE': return c_lib.vigenere_decrypt(t, params['key'])
        
        if algo == 'AES': return c_lib.aes_decrypt(enc_bytes, params['key'], AES_IV).decode('utf-8')
        elif algo == 'DES': return c_lib.des_decrypt(enc_bytes, params['key'], DES_IV).decode('utf-8')
        elif algo == 'MANUAL_DES': return m_des.decrypt(enc_bytes, params['key']).decode('utf-8')
        elif algo == 'MANUAL_AES': return m_aes.decrypt(enc_bytes, params['key']).decode('utf-8')
        elif algo == 'HILL': return c_lib.hill_decrypt(enc_bytes.decode('utf-8'), params['key'])
        return enc_bytes.decode('utf-8')
    except: return "[Şifre Çözülemedi]"

def receive_thread(sock, cat, algo, params, c_lib, m_des, m_aes, q):
    while True:
        try:
            d = sock.recv(5*1024*1024)
            if not d: break
            try:
                pkt = json.loads(d.decode('utf-8'))
                plain = decrypt_data_safe(bytes.fromhex(pkt['data']), cat, algo, params, c_lib, m_des, m_aes)
                disp = plain
                if pkt['type'] == 'FILE': disp = f"📁 DOSYA: {pkt.get('filename')}"
                q.put({"sender": pkt.get('sender'), "encrypted": pkt.get('data')[:30]+"...", "plain": disp})
            except: pass
        except: break

def connect(ip, port, cat, algo, dist, m_params):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, int(port)))
        c_mgr = st.session_state.crypto
        
        offer = json.loads(s.recv(4096).decode('utf-8'))
        srv_rsa = serialization.load_pem_public_key(offer['rsa_pub'].encode('utf-8'), backend=c_mgr.backend)
        srv_ecc = serialization.load_pem_public_key(offer['ecc_pub'].encode('utf-8'), backend=c_mgr.backend)
        
        # Server bize ismimizi verdi (Örn: Client 1)
        my_assigned_name = offer.get('assigned_name', 'Bilinmiyor')
        st.session_state.my_name = my_assigned_name
        
        params = {}
        setup = {"dist_method": dist, "algo": algo, "category": cat}
        
        if cat == 'BLOK':
            temp = b""
            if algo in ['AES', 'MANUAL_AES']: temp = os.urandom(16)
            elif algo == 'DES': temp = os.urandom(24)
            elif algo == 'MANUAL_DES': temp = os.urandom(8)
            elif algo == 'HILL': params['key'] = [3,3,2,5]

            if algo != 'HILL':
                if dist == 'RSA':
                    setup['enc_session_key'] = c_mgr.rsa_encrypt(temp, srv_rsa).hex()
                    params['key'] = temp
                elif dist == 'ECC':
                    pr, pu = c_mgr.generate_ecc_keys()
                    derived = c_mgr.derive_shared_secret(pr, srv_ecc)
                    if algo in ['AES', 'MANUAL_AES']: params['key'] = derived[:16]
                    elif algo == 'DES': params['key'] = derived[:24]
                    elif algo == 'MANUAL_DES': params['key'] = derived[:8]
                    setup['client_ecc_pub'] = pu.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode('utf-8')

        elif cat == 'KLASIK':
            if algo == 'SEZAR': params['key'] = int(m_params['shift'])
            elif algo == 'VIGENERE': params['key'] = m_params['keyword']
            setup['params'] = params

        s.send(json.dumps(setup).encode('utf-8'))
        
        st.session_state.socket = s
        st.session_state.connected = True
        st.session_state.params = params
        st.session_state.algo = algo
        st.session_state.category = cat
        
        threading.Thread(target=receive_thread, args=(s, cat, algo, params, c_mgr, st.session_state.manual_des, st.session_state.manual_aes, st.session_state.data_queue), daemon=True).start()
        st.rerun()
    except Exception as e: st.error(str(e))

with st.sidebar:
    st.header("Bağlantı Ayarları")
    ip = st.text_input("IP", "127.0.0.1")
    port = st.text_input("Port", "12345")
    
    cat = st.selectbox("Şifreleme Türü", ["BLOK", "KLASIK"])
    
    opts = []
    if cat == "BLOK": opts = ["MANUAL_AES", "AES", "MANUAL_DES", "DES", "HILL"]
    else: opts = ["SEZAR", "VIGENERE"]
    algo = st.selectbox("Algoritma", opts)
    
    dist = "RSA"
    if cat == "BLOK":
        dist = st.selectbox("Anahtar Dağıtımı", ["RSA", "ECC"])
    
    m_p = {}
    if algo == "SEZAR": m_p['shift'] = st.number_input("Shift", 1, 25, 3)
    if algo == "VIGENERE": m_p['keyword'] = st.text_input("Anahtar Kelime", "ANAHTAR")
    
    if not st.session_state.connected:
        if st.button("BAĞLAN"): connect(ip, port, cat, algo, dist, m_p)
    else:
        st.success(f"✅ Bağlı: {st.session_state.my_name}")
        st.info(f"Yöntem: {algo} ({dist})")
        
        # --- YENİ EKLENEN BUTON ---
        if st.button("🗑️ Sohbeti Temizle"):
            st.session_state.messages = []
            st.rerun()

        if st.button("Çıkış Yap"):
            st.session_state.connected = False; st.rerun()

st.title(f"🛡️ Kripto İstasyonu ({st.session_state.my_name})")

if st.session_state.connected:
    while not st.session_state.data_queue.empty():
        st.session_state.messages.append(st.session_state.data_queue.get())
        st.rerun()

    tab1, tab2 = st.tabs(["Mesajlar", "Dosya Transferi"])
    with tab1:
        for m in st.session_state.messages:
            # Gönderen 'Sen' ise sağa, başkasıysa sola
            with st.chat_message("user" if m['sender']=="Sen" else "assistant"):
                st.write(f"**{m['sender']}**") # Artık burada "Client 1" yazar
                st.code(m['encrypted'])
                with st.expander("Çöz"): st.write(m['plain'])
        with st.form("chat"):
            c1, c2 = st.columns([5,1])
            txt = c1.text_input("Mesaj")
            if c2.form_submit_button("Gönder") and txt:
                enc = encrypt_data_safe(txt, st.session_state.category, st.session_state.algo, st.session_state.params, st.session_state.crypto, st.session_state.manual_des, st.session_state.manual_aes)
                st.session_state.socket.send(json.dumps({"type":"MSG", "data": enc.hex() if isinstance(enc, bytes) else enc.encode('utf-8').hex()}).encode('utf-8'))
                st.session_state.messages.append({"sender":"Sen", "encrypted": "...", "plain": txt})
                st.rerun()
    with tab2:
        if st.session_state.category == "BLOK":
            uf = st.file_uploader("Dosya Seç")
            if uf and st.button("Şifrele ve Yolla"):
                enc = encrypt_data_safe(uf.getvalue(), st.session_state.category, st.session_state.algo, st.session_state.params, st.session_state.crypto, st.session_state.manual_des, st.session_state.manual_aes)
                st.session_state.socket.send(json.dumps({"type":"FILE", "data": enc.hex(), "filename": uf.name}).encode('utf-8'))
                st.success("Dosya Gönderildi")
        else: st.warning("Dosya gönderimi sadece BLOK şifreleme modunda aktiftir.")
    
    time.sleep(2); st.rerun()
else: st.info("Lütfen soldan bağlanın.")