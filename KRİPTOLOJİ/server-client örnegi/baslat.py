import subprocess
import sys
import time
import os
import signal

# Şu an kullanılan Python'un tam yolunu al
current_python = sys.executable

def kill_process_tree(pid):
    """
    Windows'ta bir işlemi ve onun yarattığı tüm alt işlemleri (Streamlit vb.)
    zorla kapatmak için 'taskkill' komutunu kullanır.
    """
    try:
        if os.name == 'nt': # Windows ise
            subprocess.call(['taskkill', '/F', '/T', '/PID', str(pid)], 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
        else: # Linux/Mac ise
            os.kill(pid, signal.SIGKILL)
    except Exception:
        pass

print(f"🚀 SİSTEM BAŞLATILIYOR...")
print(f"🔧 Python: {current_python}")

processes = []

try:
    # 1. SERVER'I BAŞLAT
    # Yeni pencerede aç (Windows için)
    CREATE_NEW_CONSOLE = subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
    
    print("⏳ Server açılıyor...")
    p_server = subprocess.Popen([current_python, "server.py"], creationflags=CREATE_NEW_CONSOLE)
    processes.append(p_server)
    
    time.sleep(2) 

    # 2. CLIENT 1 BAŞLAT
    print("👤 Client 1 (Ahmet) açılıyor...")
    p_client1 = subprocess.Popen([current_python, "-m", "streamlit", "run", "web_client.py"], shell=False)
    processes.append(p_client1)

    # 3. CLIENT 2 BAŞLAT
    print("👤 Client 2 (Mehmet) açılıyor...")
    p_client2 = subprocess.Popen([current_python, "-m", "streamlit", "run", "web_client.py", "--server.port", "8502"], shell=False)
    processes.append(p_client2)

    print("\n✅ SİSTEM AKTİF!")
    print("🛑 KAPATMAK İÇİN BU TERMİNALDE 'CTRL+C' YAPIN.")
    print("(Sistem donarsa terminali kapatmanız yeterlidir, işlemler otomatik temizlenir.)")

    # Ana programın kapanmaması için döngü
    while True:
        time.sleep(1)

except KeyboardInterrupt:
    print("\n\n🛑 KAPATILIYOR (Zorla)...")
    print("Lütfen bekleyin, tüm pencereler kapatılıyor...")
    
    # Listediğimiz tüm işlemleri "Terminatör" gibi gezip öldürüyoruz
    for p in processes:
        kill_process_tree(p.pid)
        
    print("✅ Tüm sistem başarıyla kapatıldı.")
    sys.exit(0)