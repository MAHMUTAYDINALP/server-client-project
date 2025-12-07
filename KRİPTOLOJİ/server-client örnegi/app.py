from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit
import socket # IP adresini otomatik bulmak için

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gizli_anahtar'

# cors_allowed_origins="*" tüm cihazların bağlanmasına izin verir
socketio = SocketIO(app, cors_allowed_origins="*")

mesajlar_db = []

# --- SENİN İLK KODUNDAKİ ALGORİTMALAR ---

def caesar(text, n):
    sonuc = ''
    n = int(n) # Sayıya çevir
    for c in text:
        if c.isalpha():
            baz = ord('A') if c.isupper() else ord('a')
            sonuc += chr((ord(c) - baz + n) % 26 + baz)
        else:
            sonuc += c
    return sonuc

def substitution(text, anahtar):
    alfabe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    sonuc = ''
    for c in text:
        if c.isalpha():
            buyuk = c.isupper()
            index = alfabe.index(c.upper())
            # Eğer anahtar kısa girildiyse hata vermesin diye mod alıyoruz
            yeni = anahtar[index % len(anahtar)]
            sonuc += yeni if buyuk else yeni.lower()
        else:
            sonuc += c
    return sonuc

def vigenere(text, kelime):
    sonuc = ''
    j = 0
    for c in text:
        if c.isalpha():
            buyuk = c.isupper()
            baz = ord('A') if buyuk else ord('a')
            k1 = ord(c.upper()) - ord('A')
            k2 = ord(kelime[j % len(kelime)].upper()) - ord('A')
            sonuc += chr((k1 + k2) % 26 + baz)
            j += 1
        else:
            sonuc += c
    return sonuc

def coz_logic(text, yontem, param):
    try:
        if yontem == 'caesar':
            return caesar(text, 26 - int(param))
        elif yontem == 'substitution':
            alfabe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            sonuc = ''
            for c in text:
                if c.isalpha():
                    buyuk = c.isupper()
                    # Ters arama
                    index = param.index(c.upper())
                    sonuc += alfabe[index] if buyuk else alfabe[index].lower()
                else:
                    sonuc += c
            return sonuc
        elif yontem == 'vigenere':
            sonuc = ''
            j = 0
            for c in text:
                if c.isalpha():
                    buyuk = c.isupper()
                    baz = ord('A') if buyuk else ord('a')
                    k1 = ord(c.upper()) - ord('A')
                    k2 = ord(param[j % len(param)].upper()) - ord('A')
                    sonuc += chr((k1 - k2 + 26) % 26 + baz)
                    j += 1
                else:
                    sonuc += c
            return sonuc
        return text
    except Exception as e:
        return "Hata: Anahtar uyumsuz!"

# --- HTML ARAYÜZÜ (Telefondan açılabilmesi için gömülü) ---
HTML_PAGE = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Kripto Mesajlaşma</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: 'Segoe UI', sans-serif; background: #f4f4f9; padding: 15px; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h2 { text-align: center; color: #333; }
        
        input, select, button { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
        button { background-color: #4CAF50; color: white; border: none; font-weight: bold; cursor: pointer; }
        button:hover { background-color: #45a049; }
        
        #sohbetAlani { height: 350px; overflow-y: scroll; border: 1px solid #eee; padding: 10px; background: #fafafa; margin-top: 20px; border-radius: 5px;}
        .mesaj { background: #fff; padding: 10px; margin-bottom: 10px; border-left: 4px solid #2196F3; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .mesaj small { color: #888; font-weight: bold; }
        .sifreli-text { color: #d32f2f; font-family: monospace; word-break: break-all; }
        .cozulmus-text { color: #388E3C; font-weight: bold; display: none; margin-top: 5px; border-top: 1px dashed #ccc; padding-top: 5px;}
        .coz-btn { background: #607d8b; font-size: 12px; padding: 5px; width: auto; margin-left: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <h2>🔒 Güvenli Sohbet</h2>
        
        <label>Yöntem Seç:</label>
        <select id="yontem" onchange="ayarDegistir()">
            <option value="caesar">Caesar (Kaydırmalı)</option>
            <option value="substitution">Substitution (Yer Değiştirme)</option>
            <option value="vigenere">Vigenere (Kelime Anahtarlı)</option>
        </select>
        
        <input type="text" id="anahtar" placeholder="Kaydırma sayısı (Örn: 3)" value="3">
        <input type="text" id="mesaj" placeholder="Mesajınızı yazın...">
        
        <button onclick="gonder()">Şifrele ve Gönder 🚀</button>

        <div id="sohbetAlani"></div>
    </div>

    <script>
        const socket = io();

        // Yöntem değişince placeholder değişsin
        function ayarDegistir() {
            const y = document.getElementById('yontem').value;
            const a = document.getElementById('anahtar');
            if(y === 'caesar') { a.placeholder = "Kaydırma Sayısı (Örn: 3)"; a.value = "3"; }
            else if(y === 'substitution') { a.placeholder = "Alfabe Sırası (26 Harf)"; a.value = "ZEBRASCDFGHIJKLMNOPQTUVWXY"; }
            else { a.placeholder = "Anahtar Kelime"; a.value = "ANAHTAR"; }
        }

        // 1. Geçmiş mesajları yükle
        socket.on('gecmis_yukle', (data) => {
            const alan = document.getElementById('sohbetAlani');
            alan.innerHTML = '';
            data.forEach(ekranaYaz);
            alan.scrollTop = alan.scrollHeight;
        });

        // 2. Yeni mesaj gelince
        socket.on('yeni_mesaj', (veri) => {
            ekranaYaz(veri);
            const alan = document.getElementById('sohbetAlani');
            alan.scrollTop = alan.scrollHeight;
        });

        // 3. Çözme cevabı gelince
        socket.on('coz_cevabi', (veri) => {
            // İlgili mesajın altındaki gizli alanı bulup açıyoruz
            const gizliAlan = document.getElementById('cozulmus-' + veri.id);
            if(gizliAlan) {
                gizliAlan.style.display = 'block';
                gizliAlan.innerText = "🔓 Açık: " + veri.metin;
            }
        });

        function gonder() {
            const m = document.getElementById('mesaj').value;
            const y = document.getElementById('yontem').value;
            const a = document.getElementById('anahtar').value;
            if(!m) return;
            
            socket.emit('mesaj_yolla', {metin: m, yontem: y, anahtar: a});
            document.getElementById('mesaj').value = '';
        }

        function ekranaYaz(veri) {
            const alan = document.getElementById('sohbetAlani');
            // Benzersiz ID oluşturuyoruz ki hangi butona bastığımızı bilelim
            const msgId = Math.random().toString(36).substr(2, 9);
            
            alan.innerHTML += `
                <div class="mesaj">
                    <small>${veri.yontem.toUpperCase()}</small>
                    <button class="coz-btn" onclick="cozIstegi('${veri.sifreli_metin}', '${veri.yontem}', '${msgId}')">Çöz</button>
                    <br>
                    <span class="sifreli-text">${veri.sifreli_metin}</span>
                    <div id="cozulmus-${msgId}" class="cozulmus-text"></div>
                </div>
            `;
        }

        function cozIstegi(sifreliText, yontem, uiId) {
            // O an input kutusunda yazan anahtarı alıp deniyoruz
            const mevcutAnahtar = document.getElementById('anahtar').value;
            
            socket.emit('coz_istegi', {
                sifre: sifreliText, 
                yontem: yontem, 
                anahtar: mevcutAnahtar,
                id: uiId
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_PAGE)

# --- WEBSOCKET OLAYLARI ---

@socketio.on('connect')
def handle_connect():
    emit('gecmis_yukle', mesajlar_db)

@socketio.on('mesaj_yolla')
def handle_mesaj(data):
    yontem = data['yontem']
    param = data['anahtar']
    metin = data['metin']
    
    # Şifreleme seçimi
    sifreli = ""
    if yontem == 'caesar':
        sifreli = caesar(metin, param)
    elif yontem == 'substitution':
        sifreli = substitution(metin, param)
    elif yontem == 'vigenere':
        sifreli = vigenere(metin, param)
    
    kayit = {'sifreli_metin': sifreli, 'yontem': yontem}
    mesajlar_db.append(kayit)
    
    emit('yeni_mesaj', kayit, broadcast=True)

@socketio.on('coz_istegi')
def handle_coz(data):
    # Kullanıcı "Çöz" tuşuna bastığında sunucuya sorar
    cozulmus = coz_logic(data['sifre'], data['yontem'], data['anahtar'])
    # Sadece soran kişiye cevabı yolla
    emit('coz_cevabi', {'metin': cozulmus, 'id': data['id']})

if __name__ == '__main__':
    # Bilgisayarın IP adresini otomatik bulup ekrana yazalım
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print(f"--------------------------------------------")
    print(f"Server Başlatıldı!")
    print(f"Bilgisayarından gir: http://localhost:5000")
    print(f"TELEFONDAN gir:      http://{local_ip}:5000")
    print(f"--------------------------------------------")
    
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)