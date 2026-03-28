# 🔐 Kriptografik Haberleşme Sistemi (Secure Client-Server Comm)

Bu proje, temel şifreleme algoritmalarından (Sezar, Vigenere) başlayıp, modern kriptografik mimarilere (AES, RSA, ECC) kadar uzanan geniş bir yelpazede geliştirilmiş, uçtan uca güvenli bir **İstemci-Sunucu (Client-Server)** haberleşme sistemidir. [cite_start]Uygulama, ağ üzerinde iletilen verilerin üçüncü şahıslar tarafından okunamayacak şekilde şifrelenmesini (Confidentiality) ve güvenli anahtar dağıtımını (Key Exchange) hedeflemektedir[cite: 103, 104].

> **🎓 Akademik Bilgi:**
> [cite_start]Bu proje, **Mahmut Aydınalp** tarafından Karadeniz Teknik Üniversitesi (KTÜ) Yazılım Mühendisliği 3. Sınıf (1. Dönem) **Kriptoloji ve Veri Güvenliği** dersi kapsamında geliştirilmiştir[cite: 101].

---

## 🏛️ Hibrit Sistem Mimarisi ve Akış

[cite_start]Sistem, Python dili ile **TCP soket programlama** altyapısı üzerine inşa edilmiş olup, kullanıcı dostu arayüz için **Streamlit** kütüphanesi kullanılmıştır[cite: 109]. [cite_start]Güvenliği maksimize etmek için **Hibrit Kriptografi** tercih edilmiştir[cite: 105]:

1.  [cite_start]**Bağlantı ve Kimliklendirme:** İstemciler sunucuya bağlandığında, sunucu her birine dinamik olarak sıralı bir kimlik (Client 1, Client 2 vb.) atar[cite: 111].
2.  [cite_start]**El Sıkışma (Handshake) & Asimetrik Şifreleme:** Sunucu, asimetrik şifreleme algoritmaları olan **RSA** ve **ECC** açık anahtarlarını istemciye gönderir[cite: 112]. [cite_start]İstemci, bu anahtarları kullanarak simetrik oturum anahtarını güvenli bir şekilde sunucuya iletir[cite: 113].
3.  [cite_start]**Güvenli Haberleşme (Simetrik Şifreleme):** Anahtar dağıtımı tamamlandıktan sonra, veri trafiği (mesajlaşma ve dosya transferi) daha hızlı olan **AES** veya **DES** algoritmaları ile şifrelenir[cite: 114].

---

## 🧠 Öne Çıkan Teknik Geliştirmeler

Bu projenin en büyük teknik çıktısı, hazır kütüphanelerin ötesine geçerek kriptografik matematiğin koda dökülmesidir.

### 1. Manuel AES Implementasyonu (Kütüphanesiz)
[cite_start]AES algoritmasının matematiksel temellerini anlamak amacıyla standart `cryptography` kütüphanesine alternatif olarak **saf Python ile manuel bir AES motoru** yazılmıştır[cite: 117, 120].
* [cite_start]**Galois Field (GF(2^8))** aritmetiği koda dökülmüştür[cite: 121].
* [cite_start]Dinamik S-Box üretimi gerçekleştirilmiştir[cite: 121].
* [cite_start]AES döngüleri olan `SubBytes`, `ShiftRows` ve `MixColumns` işlemleri sıfırdan matematiksel olarak inşa edilmiştir[cite: 121].

### 2. Algoritma Çeşitliliği
Sistem sadece modern algoritmaları değil, kriptolojinin tarihsel gelişimini göstermek adına **Substitution, Sezar ve Vigenere** gibi klasik şifreleme yöntemlerini de desteklemektedir.

---

## 📊 Performans Analizi (Kütüphane vs Manuel)

[cite_start]Hazır kütüphaneler (C tabanlı arka planları sayesinde) donanım hızlandırması kullanırken, eğitim amacıyla yazılan manuel algoritmalar işlemci üzerinde salt matematiksel hesaplama yapar[cite: 118, 124]. Aşağıdaki tablo sistem üzerindeki hız farklarını göstermektedir:

| Algoritma | Yöntem | İşlem Süresi (Saniye) | Açıklama |
| :--- | :--- | :--- | :--- |
| **AES** | Kütüphane (`cryptography`) | [cite_start]0.00015 sn [cite: 123] | [cite_start]Üretim (Production) ortamı için ideal[cite: 118]. |
| **AES** | Manuel (Saf Python) | [cite_start]0.85000 sn [cite: 123] | [cite_start]Matematiksel ispat ve eğitim amaçlı[cite: 124]. |
| **DES** | Kütüphane | [cite_start]0.00011 sn [cite: 123] | Eski standart, hızlı ama günümüzde güvensiz. |
| **DES** | Manuel | [cite_start]0.02500 sn [cite: 123] | [cite_start]Eğitim amaçlı manuel implementasyon[cite: 124]. |

---

## 🕵️‍♂️ Ağ Analizi ve Güvenlik Kanıtı (Wireshark)

[cite_start]Sistemin gerçekten güvenli çalıştığını ispatlamak amacıyla **12345 portu** üzerinden gerçekleşen TCP trafiği Wireshark ile dinlenmiştir[cite: 126]. 

[cite_start]Paket analizlerinde açıkça görülmektedir ki; ağ üzerindeki veri düz metin (Plain Text) olarak değil, şifrelenmiş anlamsız bloklar halinde taşınmaktadır[cite: 127]. [cite_start]Bu yapı, sistemi **Man-in-the-Middle (Ortadaki Adam)** saldırılarına karşı tam korumalı hale getirmektedir[cite: 128].




---

## 🚀 Kurulum ve Çalıştırma

Sistemi kendi bilgisayarınızda test etmek için aşağıdaki adımları izleyebilirsiniz:

### 1. Gereksinimler
Projeyi klonladıktan sonra sanal ortamınızı oluşturun ve gerekli kütüphaneleri yükleyin:
```bash
pip install streamlit cryptography
2. Sunucuyu Başlatma
Öncelikle ana makinede (veya localhost'ta) sunucu scriptini çalıştırarak gelen bağlantıları dinlemeye başlayın:

Bash
python server.py
3. İstemcileri Başlatma
Sunucu aktif edildikten sonra, farklı terminallerde istemci arayüzlerini başlatabilirsiniz:

Bash
streamlit run client.py
Geliştiren: Mahmut Aydınalp
