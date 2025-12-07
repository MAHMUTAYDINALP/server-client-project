from flask import Flask, render_template_string, request
from flask_socketio import SocketIO, emit
import socket # Bilgisayarın IP adresini otomatik bulup ekrana yazmak için

app = Flask(__name__)
app.config['SECRET_KEY'] = 'gizli_anahtar'

# --- WEBSOCKET YAPILANDIRMASI ---
# cors_allowed_origins="*": Farklı cihazların (Telefon gibi) sunucuya bağlanmasına izin verir.
# compression=False: Wireshark analizinde paketlerin "Maskelenmiş/Sıkıştırılmış" görünmesini engeller.
# Bu sayede ağ trafiğini düzgün analiz edebiliriz.
socketio = SocketIO(app, cors_allowed_origins="*", compression=False)

# Mesajları geçici olarak hafızada tutmak için liste (Veritabanı yerine)
mesajlar_db = []

# ==========================================
# --- 1. ŞİFRELEME ALGORİTMALARI ---
# ==========================================

def caesar(text, n):
  
    sonuc = ''
    try: n = int(n)
    except: n = 0
    for c in text:
        if c.isalpha():
            # Büyük/Küçük harf ayrımı (ASCII tablosuna göre)
            baz = ord('A') if c.isupper() else ord('a')
            sonuc += chr((ord(c) - baz + n) % 26 + baz)
        else:
            # Harf değilse (nokta, virgül) değiştirmeden ekle
            sonuc += c
    return sonuc

def substitution(text, anahtar):
    
    alfabe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    sonuc = ''
    if len(anahtar) < 26: return text # Anahtar eksikse işlem yapma
    for c in text:
        if c.isalpha():
            buyuk = c.isupper()
            index = alfabe.index(c.upper())
            yeni = anahtar[index]
            sonuc += yeni if buyuk else yeni.lower()
        else:
            sonuc += c
    return sonuc

def vigenere(text, kelime):
   
    sonuc = ''
    j = 0
    if not kelime: return text
    for c in text:
        if c.isalpha():
            buyuk = c.isupper()
            baz = ord('A') if buyuk else ord('a')
            k1 = ord(c.upper()) - ord('A')
            # Anahtar kelimenin sıradaki harfine göre kaydırma miktarı
            k2 = ord(kelime[j % len(kelime)].upper()) - ord('A')
            sonuc += chr((k1 + k2) % 26 + baz)
            j += 1
        else:
            sonuc += c
    return sonuc


# --- 2. ŞİFRE ÇÖZME MANTIĞI ---


def coz_logic(text, yontem, param):
    """
    Şifreli metni alır, seçilen yönteme göre ters işlem yaparak
    orijinal metni (Plaintext) ortaya çıkarır.
    """
    try:
        if yontem == 'caesar':
            # İleri gittiyse (26 - n) kadar daha giderek başa döner
            return caesar(text, 26 - int(param))
        elif yontem == 'substitution':
            alfabe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            sonuc = ''
            for c in text:
                if c.isalpha():
                    buyuk = c.isupper()
                    # Karışık alfabedeki yerini bulup normal alfabeye çevirir
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
                    # Şifrelerken topladık, çözerken çıkarıyoruz
                    sonuc += chr((k1 - k2 + 26) % 26 + baz)
                    j += 1
                else:
                    sonuc += c
            return sonuc
        return text
    except: return "Hata: Çözülemedi"



# SAYFA 1: GÖNDERİCİ (Telefondan girilecek sade ekran)
INDEX_HTML = """
<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mesaj Gönder</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: sans-serif; padding: 20px; background: #e0f7fa; text-align: center; }
        .kutu { background: white; padding: 20px; border-radius: 10px; max-width: 400px; margin: 0 auto; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        input, select, button { width: 100%; padding: 12px; margin: 8px 0; box-sizing: border-box; border-radius: 5px; border: 1px solid #ccc; }
        button { background: #009688; color: white; border: none; font-size: 16px; cursor: pointer; }
        button:active { background: #00796b; }
    </style>
</head>
<body>
    <div class="kutu">
        <h2>📤 Şifreli Mesaj At</h2>
        <select id="yontem" onchange="ayar()">
            <option value="caesar">Caesar</option>
            <option value="substitution">Substitution</option>
            <option value="vigenere">Vigenere</option>
        </select>
        <input type="text" id="anahtar" placeholder="Anahtar (Örn: 3)" value="3">
        <input type="text" id="mesaj" placeholder="Mesajınız...">
        <button onclick="gonder()">GÖNDER</button>
        <p id="durum" style="color:green; display:none;">Gönderildi! ✅</p>
    </div>

    <script>
        const socket = io();
        
        // Yöntem değişince varsayılan anahtarı ayarlar
        function ayar() {
            const y = document.getElementById('yontem').value;
            const a = document.getElementById('anahtar');
            if(y === 'caesar') a.value = "3";
            if(y === 'substitution') a.value = "ZEBRASCDFGHIJKLMNOPQTUVWXY";
            if(y === 'vigenere') a.value = "ANAHTAR";
        }

        function gonder() {
            const m = document.getElementById('mesaj').value;
            const y = document.getElementById('yontem').value;
            const a = document.getElementById('anahtar').value;
            
            if(!m) return;
            
            // WebSocket üzerinden sunucuya veriyi gönderir
            socket.emit('mesaj_yolla', {metin: m, yontem: y, anahtar: a});
            
            // Temizlik ve bildirim
            document.getElementById('mesaj').value = '';
            const durum = document.getElementById('durum');
            durum.style.display = 'block';
            setTimeout(() => durum.style.display = 'none', 2000);
        }
    </script>
</body>
</html>
"""

# SAYFA 2: İZLEYİCİ (Bilgisayardan takip edilecek ekran)
EKRAN_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Mesaj Ekranı</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/socket.io/4.0.1/socket.io.js"></script>
    <style>
        body { font-family: monospace; background: #222; color: #0f0; padding: 20px; }
        .container { max-width: 800px; margin: 0 auto; }
        h1 { text-align: center; border-bottom: 2px solid #0f0; padding-bottom: 10px; }
        .mesaj-kutusu { margin-top: 20px; }
        .mesaj { background: #111; border: 1px solid #333; padding: 15px; margin-bottom: 15px; border-radius: 5px; position: relative; }
        .yontem-etiket { position: absolute; top: 5px; right: 10px; font-size: 12px; color: #ff9800; }
        .sifreli { color: #e91e63; font-size: 1.2em; word-break: break-all; }
        
        .coz-panel { margin-top: 10px; border-top: 1px dashed #444; padding-top: 10px; display: flex; gap: 10px; }
        input { background: #333; border: 1px solid #555; color: white; padding: 5px; }
        button { background: #2196F3; color: white; border: none; padding: 5px 15px; cursor: pointer; }
        .acik-metin { color: #0f0; font-weight: bold; margin-left: 10px; display: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>📟 Gelen Şifreli Mesajlar</h1>
        <div id="liste" class="mesaj-kutusu">
            <p style="color:#666; text-align:center;">Bağlantı bekleniyor...</p>
        </div>
    </div>

    <script>
        const socket = io();

        // Bağlanınca eski mesajları yükle
        socket.on('gecmis_yukle', (data) => {
            document.getElementById('liste').innerHTML = '';
            data.forEach(ekle);
        });

        // Yeni mesaj gelince listeye ekle
        socket.on('yeni_mesaj', (data) => {
            ekle(data);
        });
        
        // Sunucudan gelen çözülmüş metni göster
        socket.on('coz_cevabi', (data) => {
            const span = document.getElementById('sonuc-' + data.id);
            if(span) {
                span.style.display = 'inline';
                span.innerText = "=> " + data.metin;
            }
        });

        function ekle(data) {
            const liste = document.getElementById('liste');
            if(liste.querySelector('p')) liste.innerHTML = '';

            const id = Math.random().toString(36).substr(2, 9);
            
            const html = `
                <div class="mesaj">
                    <span class="yontem-etiket">${data.yontem.toUpperCase()}</span>
                    <div>Şifreli Veri:</div>
                    <div class="sifreli">${data.sifreli_metin}</div>
                    
                    <div class="coz-panel">
                        <input type="text" id="key-${id}" placeholder="Anahtarı Girin">
                        <button onclick="coz('${data.sifreli_metin}', '${data.yontem}', '${id}')">Çöz</button>
                        <span id="sonuc-${id}" class="acik-metin"></span>
                    </div>
                </div>
            `;
            liste.insertAdjacentHTML('afterbegin', html);
        }

        // Çözme isteğini sunucuya gönderir
        function coz(sifreli, yontem, id) {
            const anahtar = document.getElementById('key-' + id).value;
            if(!anahtar) return alert("Anahtar giriniz!");
            
            socket.emit('coz_istegi', {
                sifre: sifreli,
                yontem: yontem,
                anahtar: anahtar,
                id: id
            });
        }
    </script>
</body>
</html>
"""

# ==========================================
# --- 4. ROTALAR VE SOCKET OLAYLARI ---
# ==========================================

@app.route('/')
def gonderici_sayfasi():
    """Burası Mesaj Gönderme Ekranı (Index) - Telefondan girilir"""
    return render_template_string(INDEX_HTML)

@app.route('/ekran')
def alici_sayfasi():
    """Burası Mesajları İzleme Ekranı - Bilgisayardan izlenir"""
    return render_template_string(EKRAN_HTML)

@socketio.on('connect')
def baglanti():
    """Kullanıcı siteye girdiğinde çalışır"""
    emit('gecmis_yukle', mesajlar_db)

@socketio.on('mesaj_yolla')
def mesaj_al(data):
    """
    Telefondan gelen şifresiz mesajı alır,
    SUNUCUDA şifreler ve veritabanına kaydeder.
    """
    sifreli = ""
    y = data['yontem']
    p = data['anahtar']
    m = data['metin']
    
    # Seçilen yönteme göre şifreleme fonksiyonunu çağır
    if y == 'caesar': sifreli = caesar(m, p)
    elif y == 'substitution': sifreli = substitution(m, p)
    elif y == 'vigenere': sifreli = vigenere(m, p)
    else: sifreli = m
    
    kayit = {'sifreli_metin': sifreli, 'yontem': y}
    mesajlar_db.append(kayit)
    
    # broadcast=True: Mesajı bağlı olan HERKESE (özellikle İzleyici ekranına) gönder
    emit('yeni_mesaj', kayit, broadcast=True)

@socketio.on('coz_istegi')
def coz_istegi(data):
    """Kullanıcı 'Çöz' butonuna bastığında çalışır"""
    acik = coz_logic(data['sifre'], data['yontem'], data['anahtar'])
    # Sadece soran kişiye cevabı yolla (broadcast yok)
    emit('coz_cevabi', {'metin': acik, 'id': data['id']})

if __name__ == '__main__':
    # Bilgisayarın IP adresini otomatik bulup terminale yazar
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    print(f"Server Açıldı: http://{local_ip}:5000")
    print(f"1. Telefondan gir (Gönderici): http://{local_ip}:5000/")
    print(f"2. Bilgisayardan gir (Alıcı):  http://{local_ip}:5000/ekran")
    
    # allow_unsafe_werkzeug=True: Geliştirme ortamında WebSocket hatalarını önler
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, allow_unsafe_werkzeug=True)