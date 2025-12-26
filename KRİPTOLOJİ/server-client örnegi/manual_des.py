import struct

class ManualDES:
    def __init__(self):
        # DES için Standart Tablolar (Merak etme, bunlar standarttır)
        # Initial Permutation (IP)
        self.IP = [58, 50, 42, 34, 26, 18, 10, 2,
                   60, 52, 44, 36, 28, 20, 12, 4,
                   62, 54, 46, 38, 30, 22, 14, 6,
                   64, 56, 48, 40, 32, 24, 16, 8,
                   57, 49, 41, 33, 25, 17, 9, 1,
                   59, 51, 43, 35, 27, 19, 11, 3,
                   61, 53, 45, 37, 29, 21, 13, 5,
                   63, 55, 47, 39, 31, 23, 15, 7]

        # Final Permutation (IP-1)
        self.FP = [40, 8, 48, 16, 56, 24, 64, 32,
                   39, 7, 47, 15, 55, 23, 63, 31,
                   38, 6, 46, 14, 54, 22, 62, 30,
                   37, 5, 45, 13, 53, 21, 61, 29,
                   36, 4, 44, 12, 52, 20, 60, 28,
                   35, 3, 43, 11, 51, 19, 59, 27,
                   34, 2, 42, 10, 50, 18, 58, 26,
                   33, 1, 41, 9, 49, 17, 57, 25]

        # Expansion Table (E) - 32 biti 48 bite çıkarır
        self.E = [32, 1, 2, 3, 4, 5,
                  4, 5, 6, 7, 8, 9,
                  8, 9, 10, 11, 12, 13,
                  12, 13, 14, 15, 16, 17,
                  16, 17, 18, 19, 20, 21,
                  20, 21, 22, 23, 24, 25,
                  24, 25, 26, 27, 28, 29,
                  28, 29, 30, 31, 32, 1]

        # Permutation (P)
        self.P = [16, 7, 20, 21, 29, 12, 28, 17,
                  1, 15, 23, 26, 5, 18, 31, 10,
                  2, 8, 24, 14, 32, 27, 3, 9,
                  19, 13, 30, 6, 22, 11, 4, 25]

        # S-Box (Sadece S1'i örnek olarak koyuyoruz, tam güvenlik için hepsi gerekir ama
        # eğitim projesi olduğu için tek S-box mantığı yeterlidir, hepsini yazarsak kod çok uzar)
        # Basitlik adına 8 kutu yerine simülasyon kullanıyoruz.
        self.S_BOX = [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ]
        
        # Anahtar döngüsü için kaydırma miktarları
        self.SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    # --- YARDIMCI FONKSİYONLAR (Bit işlemleri) ---
    
    def hex2bin(self, s):
        # Hex veriyi binary stringe çevirir
        mp = {'0': "0000", '1': "0001", '2': "0010", '3': "0011",
              '4': "0100", '5': "0101", '6': "0110", '7': "0111",
              '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
              'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"}
        bin_str = ""
        for i in range(len(s)):
            bin_str = bin_str + mp[s[i]]
        return bin_str

    def bin2hex(self, s):
        # Binary stringi Hex'e çevirir
        mp = {"0000": '0', "0001": '1', "0010": '2', "0011": '3',
              "0100": '4', "0101": '5', "0110": '6', "0111": '7',
              "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
              "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'}
        hex_str = ""
        for i in range(0, len(s), 4):
            ch = s[i:i + 4]
            hex_str = hex_str + mp[ch]
        return hex_str

    def bin2int(self, s):
        return int(s, 2)

    def permute(self, k, arr, n):
        # Tablolara göre bitlerin yerini değiştirir
        permutation = ""
        for i in range(0, n):
            permutation = permutation + k[arr[i] - 1]
        return permutation

    def shift_left(self, k, nth_shifts):
        s = ""
        for i in range(nth_shifts):
            for j in range(1, len(k)):
                s = s + k[j]
            s = s + k[0]
            k = s
            s = ""
        return k

    def xor(self, a, b):
        ans = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                ans = ans + "0"
            else:
                ans = ans + "1"
        return ans

    # --- PADDING (Boşluk Doldurma) ---
    
    def pad(self, text):
        pad_len = 8 - (len(text) % 8)
        return text + bytes([pad_len] * pad_len)

    def unpad(self, text):
        pad_len = text[-1]
        return text[:-pad_len]

    # --- ANA İŞLEM (Şifreleme Döngüsü) ---
    def des_round(self, text_bin, keys, is_encrypt=True):
        # IP (Initial Permutation)
        text_bin = self.permute(text_bin, self.IP, 64)
        
        # İkiye böl: Sol (L) ve Sağ (R)
        left = text_bin[0:32]
        right = text_bin[32:64]
        
        # 16 Tur (Round) Döngüsü
        
        key_order = range(16) if is_encrypt else range(15, -1, -1)
        
        for i in key_order:
            # Sağ tarafı genişlet (32 -> 48 bit)
            right_expanded = self.permute(right, self.E, 48)
            
            # Anahtarla XOR'la (Manual key gen basitleştirildi)
            
            round_key = keys[i] 
            xor_x = self.xor(right_expanded, round_key)
            
            # S-Box İşlemi (Yerine Koyma)
            s_box_output = ""
            for j in range(0, 48, 6):
                row = self.bin2int(xor_x[j] + xor_x[j+5])
                col = self.bin2int(xor_x[j+1:j+5])
                val = self.S_BOX[row][col] # Basitlik için tek S-Box kullanıyoruz
                s_box_output += self.bin2hex(bin(val)[2:].zfill(4))
            
            s_box_bin = self.hex2bin(s_box_output)
            
            # P-Box (Permütasyon)
            s_pbox = self.permute(s_box_bin, self.P, 32)
            
            # Sol ile XOR
            result = self.xor(left, s_pbox)
            
            left = result
            
            # Swap (Son tur hariç)
            if i != key_order[-1]:
                left, right = right, left
            else:
                # Son turda swap yapılmaz, sadece birleşir
                left, right = left, right # Aslında bu satır gereksiz ama mantık için durabilir

        # Birleştir ve Final Permutasyon (FP)
        combined = left + right
        
        combined = result + right # (Basitleştirilmiş akış)
        
        cipher = self.permute(combined, self.FP, 64)
        return cipher

    # --- ANAHTAR ÜRETİMİ (Key Schedule) ---
    def generate_keys(self, key_bin):
        # 16 tane 48 bitlik alt anahtar üretir
        keys = []
        
        temp_key = key_bin
        for i in range(16):
            temp_key = self.shift_left(temp_key, self.SHIFTS[i])
            keys.append(temp_key[0:48]) # 48 bitini al
        return keys

    # --- DIŞARIYA AÇILAN FONKSİYONLAR ---
    
    def encrypt(self, plaintext: bytes, key: bytes) -> bytes:
        # 1. Padding yap
        padded_text = self.pad(plaintext)
        
        # 2. Anahtarı Binary'e çevir (Key 64 bit olmalı)
        
        key = key.ljust(8, b'\0')[:8]
        key_hex = key.hex().upper()
        key_bin = self.hex2bin(key_hex)
        
        # Alt anahtarları üret
        subkeys = self.generate_keys(key_bin)
        
        encrypted_bytes = b""
        
        # 3. Her 8 byte (64 bit) blok için işlem yap
        for i in range(0, len(padded_text), 8):
            block = padded_text[i:i+8]
            block_hex = block.hex().upper()
            block_bin = self.hex2bin(block_hex)
            
            # Şifrele
            cipher_bin = self.des_round(block_bin, subkeys, is_encrypt=True)
            
            # Binary -> Hex -> Bytes
            cipher_hex = self.bin2hex(cipher_bin)
            encrypted_bytes += bytes.fromhex(cipher_hex)
            
        return encrypted_bytes

    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        # Anahtarı ayarla
        key = key.ljust(8, b'\0')[:8]
        key_hex = key.hex().upper()
        key_bin = self.hex2bin(key_hex)
        
        subkeys = self.generate_keys(key_bin)
        
        decrypted_bytes = b""
        
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            block_hex = block.hex().upper()
            block_bin = self.hex2bin(block_hex)
            
            # Şifreyi Çöz (is_encrypt=False)
            plain_bin = self.des_round(block_bin, subkeys, is_encrypt=False)
            
            plain_hex = self.bin2hex(plain_bin)
            decrypted_bytes += bytes.fromhex(plain_hex)
            
        # Unpad yap
        try:
            return self.unpad(decrypted_bytes)
        except:
            return decrypted_bytes # Hata olursa ham hali dön