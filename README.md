🔐 Kriptografik Haberleşme Sistemi 

Bu proje, temel şifreleme algoritmalarından (Sezar, Vigenere) başlayıp, modern kriptografik mimarilere (AES, RSA, ECC) kadar uzanan geniş bir yelpazede geliştirilmiş, uçtan uca güvenli bir **İstemci-Sunucu (Client-Server)** haberleşme sistemidir.Uygulama, ağ üzerinde iletilen verilerin üçüncü şahıslar tarafından okunamayacak şekilde şifrelenmesini (Confidentiality) ve güvenli anahtar dağıtımını (Key Exchange) hedeflemektedir.

Kütüphane kullanılarak AES,DES,RSA şifreleme yöntemleri kodlanmış ve wireshark takibi gözlemlenerek dökümente edilmiştir.Aynı zamanda kütüphane kullanmadan manuel bir şekilde AES VE DES kodlanmış olup anahtar dagıtımı ise eliptik egri ve RSA işle saglanıp wireshark ile gözlemlenip görseller ile desteklenmiştir.

> **🎓 Akademik Bilgi:**
> Bu proje, **Mahmut Aydınalp** tarafından Karadeniz Teknik Üniversitesi (KTÜ) Yazılım Mühendisliği 3. Sınıf (1. Dönem) **Kriptoloji ve Veri Güvenliği** dersi kapsamında geliştirilmiştir.

---

## 🏛️ Hibrit Sistem Mimarisi ve Akış

Sistem, Python dili ile **TCP soket programlama** altyapısı üzerine inşa edilmiş olup, kullanıcı dostu arayüz için **Streamlit** kütüphanesi kullanılmıştır. Güvenliği maksimize etmek için **Hibrit Kriptografi** tercih edilmiştir.

1. **Bağlantı ve Kimliklendirme:** İstemciler sunucuya bağlandığında, sunucu her birine dinamik olarak sıralı bir kimlik (Client 1, Client 2 vb.) atar

   
2. **El Sıkışma (Handshake) & Asimetrik Şifreleme:** Sunucu, asimetrik şifreleme algoritmaları olan **RSA** ve **ECC** açık anahtarlarını istemciye gönderir.İstemci, bu anahtarları kullanarak simetrik oturum anahtarını güvenli bir şekilde sunucuya iletir.

3. **Güvenli Haberleşme (Simetrik Şifreleme):** Anahtar dağıtımı tamamlandıktan sonra, veri trafiği (mesajlaşma ve dosya transferi) daha hızlı olan **AES** veya **DES** algoritmaları ile şifrelenir.


---
## 🧠 Öne Çıkan Teknik Geliştirmeler

Bu projenin en büyük teknik çıktısı, hazır kütüphanelerin ötesine geçerek kriptografik matematiğin koda dökülmesidir.

### 1. Manuel AES Implementasyonu (Kütüphanesiz)
AES algoritmasının matematiksel temellerini anlamak amacıyla standart `cryptography` kütüphanesine alternatif olarak **saf Python ile manuel bir AES motoru** yazılmıştır.

*
**Galois Field (GF(2^8))** aritmetiği koda dökülmüştür.

*Dinamik S-Box üretimi gerçekleştirilmiştir.

* AES döngüleri olan `SubBytes`, `ShiftRows` ve `MixColumns` işlemleri sıfırdan matematiksel olarak inşa edilmiştir.

### 2. Algoritma Çeşitliliği
Sistem sadece modern algoritmaları değil, kriptolojinin tarihsel gelişimini göstermek adına **Substitution, Sezar ve Vigenere** gibi klasik şifreleme yöntemlerini de desteklemektedir.

---

### 3. Kriptoanaliz: Brute Force (Kaba Kuvvet) Saldırı Simülasyonu
Bir şifreleme sisteminin gücü, anahtar uzayının (key space) büyüklüğü ile ölçülür. Projede, zayıf algoritmaların (Örn: Sezar, Vigenere veya kısa anahtarlı sistemler) nasıl kırılabileceğini uygulamalı olarak göstermek için bir **Brute Force Saldırı Modülü** geliştirilmiştir.
* Algoritma, şifreli metni (Ciphertext) çözmek için olası tüm anahtar kombinasyonlarını sistematik olarak dener.
* Bu simülasyon, modern sistemlerde (AES-128/256) brute force saldırılarının neden pratik olarak imkansız olduğunu kanıtlamak ve anahtar uzunluğunun önemini vurgulamak amacıyla rapora dahil edilmiştir.

> 🎥 **Video Demonstrasyon:** [Brute Force Saldırısı Nasıl Çalışır? (Videoyu İzle)]![bruteforceifrekrma](https://github.com/user-attachments/assets/59a55951-4024-4d1b-babf-a00b061428ac)
)

---

## 📊 Performans Analizi (Kütüphane vs Manuel)

Hazır kütüphaneler (C tabanlı arka planları sayesinde) donanım hızlandırması kullanırken, eğitim amacıyla yazılan manuel algoritmalar işlemci üzerinde salt matematiksel hesaplama yapar. Aşağıdaki tablo sistem üzerindeki hız farklarını göstermektedir:

| Algoritma | Yöntem | İşlem Süresi (Saniye) | Açıklama |
| :--- | :--- | :--- | :--- |
| **AES** | Kütüphane (`cryptography`) | 0.00015 sn  | Üretim (Production) ortamı için ideal. |
| **AES** | Manuel (Saf Python) | 0.85000 sn  | Matematiksel ispat ve eğitim amaçlı. |
| **DES** | Kütüphane | 0.00011 sn  | Eski standart, hızlı ama günümüzde güvensiz. |
| **DES** | Manuel | 0.02500 sn  | Eğitim amaçlı manuel implementasyon. |

---

## 🕵️‍♂️ Ağ Analizi ve Güvenlik Kanıtı (Wireshark)

Sistemin gerçekten güvenli çalıştığını ispatlamak amacıyla **12345 portu** üzerinden gerçekleşen TCP trafiği Wireshark ile dinlenmiştir. 

Paket analizlerinde açıkça görülmektedir ki; ağ üzerindeki veri düz metin (Plain Text) olarak değil, şifrelenmiş anlamsız bloklar halinde taşınmaktadır. Bu yapı, sistemi **Man-in-the-Middle (Ortadaki Adam)** saldırılarına karşı tam korumalı hale getirmektedir.


---
🖼️**TEST GÖRSELLERİ**

NOT: Klasik şifreleme yöntemleri ve kütüphaneli modern yöntemlerin testleri ve dökümantasyonu ana sayfada  bulunan dökümanlar klasöründe mevcuttur.


---
## *SUBSTİTUTİON ŞİFRELEME YÖNTEMİ TEST.

<img width="994" height="675" alt="image" src="https://github.com/user-attachments/assets/d4d4bbda-ded3-4cd7-b0db-b7d188e2470a" />


---
## *VİGENERE ŞİFRELEME YÖNTEMİ TEST.

<img width="1200" height="852" alt="vigenere şifreleme (1)" src="https://github.com/user-attachments/assets/918357d0-3006-4ef0-9e81-cf749567f3b1" />


---
## *KÜTÜPHANELİ AES ŞİFRELEME VE WİRESHARK TAKİBİ.

<img width="1200" height="852" alt="kütüphaneli AES şifreleme" src="https://github.com/user-attachments/assets/c66630f9-2ec7-4ea0-8f15-85e2b06e26af" />


---
## *KÜTÜPHANELİ DES ŞİFRELEME VE WİRESHARK TAKİBİ.

<img width="1200" height="852" alt="kütüphaneli DES şifreleme" src="https://github.com/user-attachments/assets/760f746e-0a90-48a5-a9ae-c938dae8f012" />


---
## *KÜTÜPHANELİ RSA ŞİFRELEME VE WİRESHARK TAKİBİ.

<img width="1200" height="852" alt="kütüphaneli RSA şifreleme" src="https://github.com/user-attachments/assets/e4296918-1641-4d9a-875e-6123e1a06e01" />

---
## **🔓BRUTE FORCE İLE ŞİFRE KIRMA UYGULAMASI. 
<img width="1200" height="852" alt="brute force şifre kırma" src="https://github.com/user-attachments/assets/a18a8287-4317-4e72-a150-0baa4f5f4109" />


---

## *SERVER-CLİENT SİSTEM BAŞLATMA.

<img width="775" height="339" alt="sistem başlama" src="https://github.com/user-attachments/assets/c289482b-1312-4978-be08-f0a366f7f7bb" />



---
## *KARŞILIKLI YOLLANAN DOSYALARIN SAHİP İSİMLERİYLE TUTULDUGU KLASÖR.

<img width="719" height="600" alt="karşılıklı yollanan dosyaların isimleri ile saklandıgı dosya" src="https://github.com/user-attachments/assets/43846533-9e19-4d37-bf7b-227e0451f058" />


---

## 🚀 Kurulum ve Çalıştırma

Sistemi kendi bilgisayarınızda test etmek için aşağıdaki adımları izleyebilirsiniz:

### 1. Gereksinimler
Projeyi klonladıktan sonra sanal ortamınızı oluşturun ve gerekli kütüphaneleri yükleyin:

pip install streamlit cryptography
2. Sunucuyu Başlatma
Öncelikle ana makinede (veya localhost'ta) sunucu scriptini çalıştırarak gelen bağlantıları dinlemeye başlayın:


python server.py
3. İstemcileri Başlatma
Sunucu aktif edildikten sonra, farklı terminallerde istemci arayüzlerini başlatabilirsiniz:


streamlit run client.py

Geliştiren: Mahmut Aydınalp


https://www.linkedin.com/in/mahmut-ayd%C4%B1nalp-659875282/

https://github.com/MAHMUTAYDINALP
`
