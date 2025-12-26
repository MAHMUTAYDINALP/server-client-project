# manual_aes.py
# FİNAL GARANTİLİ VERSİYON
# Tüm işlemler saf GF(2^8) matematiği ile yapılır. Hata payı yoktur.

class ManualAES:
    def __init__(self):
        self.irreducible_poly = 0x11B
        self.S_BOX = [0] * 256
        self.INV_S_BOX = [0] * 256
        # S-Box'ları matematiksel olarak oluştur (Hoca İsteği)
        self._generate_sboxes_mathematically()

    # --- TEMEL MATEMATİK (GALOIS FIELD) ---
    def gmul(self, a, b):
        """GF(2^8) Çarpma İşlemi - En güvenilir yöntem"""
        p = 0
        for _ in range(8):
            if (b & 1): p ^= a
            hi_bit_set = (a & 0x80)
            a = (a << 1) & 0xFF
            if hi_bit_set: a ^= self.irreducible_poly
            b >>= 1
        return p & 0xFF

    def ginv(self, a):
        """GF(2^8) Ters Alma"""
        if a == 0: return 0
        for i in range(1, 256):
            if self.gmul(a, i) == 1: return i
        return 0

    def rotl8(self, x, shift):
        return ((x << shift) | (x >> (8 - shift))) & 0xFF

    def _generate_sboxes_mathematically(self):
        for i in range(256):
            inv = self.ginv(i)
            # Afin Dönüşümü (AES Standardı)
            s = inv ^ self.rotl8(inv, 1) ^ self.rotl8(inv, 2) ^ self.rotl8(inv, 3) ^ self.rotl8(inv, 4) ^ 0x63
            self.S_BOX[i] = s
            self.INV_S_BOX[s] = i

    # --- AES DÖNGÜLERİ ---
    def sub_bytes(self, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = self.S_BOX[state[r][c]]

    def inv_sub_bytes(self, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = self.INV_S_BOX[state[r][c]]

    def shift_rows(self, s):
        s[1] = s[1][1:] + s[1][:1]
        s[2] = s[2][2:] + s[2][:2]
        s[3] = s[3][3:] + s[3][:3]

    def inv_shift_rows(self, s):
        s[1] = s[1][-1:] + s[1][:-1]
        s[2] = s[2][-2:] + s[2][:-2]
        s[3] = s[3][-3:] + s[3][:-3]

    def add_round_key(self, s, k):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= k[c][r]

    def mix_columns(self, s):
        # Sabit Matris: 2, 3, 1, 1
        for c in range(4):
            col = [s[0][c], s[1][c], s[2][c], s[3][c]]
            s[0][c] = self.gmul(col[0], 2) ^ self.gmul(col[1], 3) ^ self.gmul(col[2], 1) ^ self.gmul(col[3], 1)
            s[1][c] = self.gmul(col[0], 1) ^ self.gmul(col[1], 2) ^ self.gmul(col[2], 3) ^ self.gmul(col[3], 1)
            s[2][c] = self.gmul(col[0], 1) ^ self.gmul(col[1], 1) ^ self.gmul(col[2], 2) ^ self.gmul(col[3], 3)
            s[3][c] = self.gmul(col[0], 3) ^ self.gmul(col[1], 1) ^ self.gmul(col[2], 1) ^ self.gmul(col[3], 2)

    def inv_mix_columns(self, s):
        # Sabit Matris: 14, 11, 13, 9 (0x0e, 0x0b, 0x0d, 0x09)
        for c in range(4):
            col = [s[0][c], s[1][c], s[2][c], s[3][c]]
            s[0][c] = self.gmul(col[0], 0x0e) ^ self.gmul(col[1], 0x0b) ^ self.gmul(col[2], 0x0d) ^ self.gmul(col[3], 0x09)
            s[1][c] = self.gmul(col[0], 0x09) ^ self.gmul(col[1], 0x0e) ^ self.gmul(col[2], 0x0b) ^ self.gmul(col[3], 0x0d)
            s[2][c] = self.gmul(col[0], 0x0d) ^ self.gmul(col[1], 0x09) ^ self.gmul(col[2], 0x0e) ^ self.gmul(col[3], 0x0b)
            s[3][c] = self.gmul(col[0], 0x0b) ^ self.gmul(col[1], 0x0d) ^ self.gmul(col[2], 0x09) ^ self.gmul(col[3], 0x0e)

    def key_expansion(self, key):
        key_columns = [[key[4*i + j] for j in range(4)] for i in range(4)]
        r_con = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a]
        i = 1
        while len(key_columns) < 44:
            word = list(key_columns[-1])
            if len(key_columns) % 4 == 0:
                word.append(word.pop(0))
                word = [self.S_BOX[b] for b in word]
                word[0] ^= r_con[i]
                i += 1
            for j in range(4): word[j] ^= key_columns[-4][j]
            key_columns.append(word)
        return [key_columns[4*i : 4*(i+1)] for i in range(11)]

    def encrypt_block(self, plaintext, key):
        state = [[plaintext[i + 4*j] for j in range(4)] for i in range(4)]
        key_schedules = self.key_expansion(key)
        
        self.add_round_key(state, key_schedules[0])
        for r in range(1, 10):
            self.sub_bytes(state)
            self.shift_rows(state)
            self.mix_columns(state)
            self.add_round_key(state, key_schedules[r])
        self.sub_bytes(state)
        self.shift_rows(state)
        self.add_round_key(state, key_schedules[10])
        return bytes(state[j][i] for i in range(4) for j in range(4))

    def decrypt_block(self, ciphertext, key):
        state = [[ciphertext[i + 4*j] for j in range(4)] for i in range(4)]
        key_schedules = self.key_expansion(key)
        
        self.add_round_key(state, key_schedules[10])
        self.inv_shift_rows(state)
        self.inv_sub_bytes(state)
        
        for r in range(9, 0, -1):
            self.add_round_key(state, key_schedules[r])
            self.inv_mix_columns(state)
            self.inv_shift_rows(state)
            self.inv_sub_bytes(state)
            
        self.add_round_key(state, key_schedules[0])
        return bytes(state[j][i] for i in range(4) for j in range(4))

    def encrypt(self, data, key):
        if len(key) != 16: key = key[:16].ljust(16, b'\0')
        pad_len = 16 - (len(data) % 16)
        data += bytes([pad_len] * pad_len)
        encrypted = b""
        for i in range(0, len(data), 16):
            encrypted += self.encrypt_block(data[i:i+16], key)
        return encrypted

    def decrypt(self, data, key):
        if len(key) != 16: key = key[:16].ljust(16, b'\0')
        decrypted = b""
        for i in range(0, len(data), 16):
            decrypted += self.decrypt_block(data[i:i+16], key)
        
        # Unpadding
        if len(decrypted) > 0:
            pad_len = decrypted[-1]
            if 0 < pad_len <= 16 and decrypted[-pad_len:] == bytes([pad_len]*pad_len):
                return decrypted[:-pad_len]
        return decrypted