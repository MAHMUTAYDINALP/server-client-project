from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
mesajlar = []

# --- Şifreleme ve çözme fonksiyonları ---

def caesar(text, n):
    sonuc = ''
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
            yeni = anahtar[index]
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


def coz(text, yontem, param):
    if yontem == 'caesar':
        return caesar(text, 26 - int(param))
    elif yontem == 'substitution':
        alfabe = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        sonuc = ''
        for c in text:
            if c.isalpha():
                buyuk = c.isupper()
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


# --- API endpoint'leri ---

@app.route('/gonder', methods=['POST'])
def gonder():
    data = request.get_json()
    mesajlar.append(data)
    print(f"Şifreli: {data['sifre']}")
    print(f"Açık: {coz(data['sifre'], data['yontem'], data['param'])}")
    return jsonify({'ok': True})


@app.route('/al', methods=['GET'])
def al():
    return jsonify({'mesajlar': mesajlar})


@app.route('/coz', methods=['POST'])
def cozmesaji():
    data = request.get_json()
    cozulmus = coz(data['sifre'], data['yontem'], data['param'])
    print(f"Çözme isteği alındı: {data}")
    print(f"Çözülmüş mesaj: {cozulmus}")
    return jsonify({'cozulmus': cozulmus})


if __name__ == '__main__':
    print("Server: http://127.0.0.1:8000")
    app.run(host='127.0.0.1', port=8000, debug=True)
