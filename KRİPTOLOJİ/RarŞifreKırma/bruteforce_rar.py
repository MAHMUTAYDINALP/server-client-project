import subprocess      #7z ve winrar kullanmak için kütüphane
from pathlib import Path        #pc de bir yola gidip açmak için kütüphane  
import sys                      #çıkış yapıp hata döndürmek için kütüphane



rar_path = Path(r"C:\Users\MONSTER\Desktop\3.SINIF\KRİPTOLOJİ\RarŞifreKırma\cimbomdeneme.rar")      #şifresini kıracagımız dosyanın yolunu degişkene atadım
wordlist_path = Path(r"C:\Users\MONSTER\Desktop\3.SINIF\KRİPTOLOJİ\RarŞifreKırma\count1.txt")       #deneycegim şifrelerin oldugu listeyi degişkene atadım
sevenzip = r"C:\Program Files\7-Zip\7z.exe"                         #7-zip kullanabilmek için derleyiciye tanıttık yerini



if not Path(sevenzip).exists():                 #aldıgım hataların nereden oldugunu anlamak için ekledim.kırılacak dosyanını olmaması,şifre listesinin olması,7-z nin olmaması*.
    print("Hata: 7z bulunamadı:", sevenzip); sys.exit(1)
if not rar_path.exists():
    print("Hata: rar dosyası bulunamadı:", rar_path); sys.exit(1)
if not wordlist_path.exists():
    print("Hata: wordlist bulunamadı:", wordlist_path); sys.exit(1)

#print("Kullanılan 7z:", sevenzip)           
#print("RAR:", rar_path)
#print("Wordlist:", wordlist_path)


with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:          #kırılacak dosyayı alıp satır satır  alıp türkçe dilinde hata olmnasın diye okuyor döngü hata olursa ignore döndürüyor
    for i, line in enumerate(f, 1):
        raw = line.rstrip("\r\n")   
        if not raw.strip():             #satır boşsa atlayan şart
            continue
        
        parts = raw.split()         #satırı parçalayıp onları parça degişkenine atıyorum
        pwd = parts[-1]  
        pwd = pwd.strip('"\' ')         #fazladan yazılan işaretleri falan temizliyor

        
        cmd = [sevenzip, "t", f"-p{pwd}", str(rar_path)]        #açacıgımız dosyayı ve açma özelliklerini cmd degişkenine atadım 
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=25)  #subprocess ile dosyayı sevenzip ile çalıştırıyrouz .stdout=subprocess.pıpe ile çıktıyı alıyoruz.stderr hatayı alıp çıktı kısmına veriyor toplamak için 
        except Exception as e:              #hata veririse diye hata mesajı yazdık 
            print(f"[{i}] Komut hatası (geçildi): {e}")
            continue

        out = proc.stdout.decode(errors="ignore")   #okumadan gelen çıktıyı hata veya şifre veya devam et komutunu stringe çeviriyor 
        
        if i % 100 == 0 or i <= 5:
            print(f"[{i}] Denendi: '{pwd}'  ")

        # 7z başarılıysa returncode 0 olur; ayrıca 'Everything is Ok' mesajı güvenli gösterge
        if proc.returncode == 0 or "Everything is Ok" in out or "Everything is ok" in out or "No errors" in out:    # şifre bulundugunda gelebilecek olan çıktıları kontrol edip şiferiyi deneme sayısı yazdırıyorum
            print("\n Şifre bulundu:", pwd)
            print("Denenen parola sayısı:", i)
            sys.exit(0)

print("\nŞifre bulunamadı.")
