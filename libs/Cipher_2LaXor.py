class LAXORCipher:
    BLOCK_LENGTH_LONGS = 4
    KEY_LEN_128_BITS = 2
    KEY_LEN_192_BITS = 3
    KEY_LEN_256_BITS = 4
    NUM_SUBKEYS = 16
    C = 4142135623730950488
    LONG_LONG_SIZE = 64
    ROUND_NUM = 3

    def compress(self,x):
        x = (x >> 32) + x
        x = (x >> 11) ^ x
        x = (x >> 9) + x
        return ((x >> 6) + x) & b'\x3f'
    
    def avalanche(self,v,a):
        v += a
        shiftAmount = self.compress(a)
        return (v << shiftAmount) | (v >> (self.LONG_LONG_SIZE - shiftAmount))

    def unavalanche(self,v,a):
        shiftAmount = self.compress(a)
        v = (v >> shiftAmount) | (v << (self.LONG_LONG_SIZE - shiftAmount))
        return v - a
    
    def next(self,a,b,c,d,e):
        t = b
        S_2 = c
        S_3 = d
        S_4 = e
        S_5 = a
        S_1 = self.avalanche(a,a+t)
        return S_1, S_2, S_3, S_4, S_5

    def expand_key(self, key, keyLen):
        subkey = []
        if keyLen == self.KEY_LEN_128_BITS:
            S_1 = key[0]
            S_2 = key[1]
            S_3 = self.C
            S_4 = self.C
            S_5 = self.C
        elif keyLen == self.KEY_LEN_192_BITS:
            S_1 = key[0]
            S_2 = key[1]
            S_3 = key[2]
            S_4 = self.C
            S_5 = self.C
        else:
            S_1 = key[0]
            S_2 = key[1]
            S_3 = key[2]
            S_4 = key[3]
            S_5 = self.C

        for i in range(10):
            S_1, S_2, S_3, S_4, S_5 = self.next(S_1,S_2,S_3,S_4,S_5) 

        for i in range(self.NUM_SUBKEYS):
            S_1, S_2, S_3, S_4, S_5 = self.next(S_1,S_2,S_3,S_4,S_5)
            subkey.append(S_1)
        
        return subkey

    def _round_encrypt(self,a,b,c,d,subkey,start):
        _a = a
        _b = b
        _c = c
        _d = d
        temp = _c + _d
        _a = self.avalanche(_a,temp+_b+subkey[start])
        _b = self.avalanche(_b,temp+_a+subkey[start+1])
        temp = _a + _b
        _c = self.avalanche(_c,temp+_d+subkey[start+2])
        _d = self.avalanche(_d,temp+_c+subkey[start+3])
        return _a,_b,_c,_d 

    def _round_decrypt(self,a,b,c,d,subkey,start):
        _a = a
        _b = b
        _c = c
        _d = d
        temp = _a + _b
        _d = self.unavalanche(_d,temp+_c+subkey[start])
        _c = self.unavalanche(_c,temp+_d+subkey[start-1])
        temp = _c + _d
        _b = self.unavalanche(_b,temp+_a+subkey[start-2])
        _a = self.unavalanche(_a,temp+_b+subkey[start-3])
        return _a,_b,_c,_d 

    def __init__(self,key):
        

    def encrypt(self, plaintext, offset, length, subkey):
        end = offset + length
        _ciphertext = plaintext.copy()
        for i in range(0 , end, self.BLOCK_LENGTH_LONGS):
            one = i + 1
            two = i + 2
            three = i + 3
            a = _ciphertext[offset]
            b = _ciphertext[one]
            c = _ciphertext[two]
            d = _ciphertext[three]

            for round_num in range(self.ROUND_NUM):
                a,b,c,d = self._round_encrypt(a,b,c,d,subkey,0+i*4)

            subkey_start = 0+self.ROUND_NUM*4
            _ciphertext[offset] = a ^ subkey[subkey_start]
            _ciphertext[one] = b ^ subkey[subkey_start+1]           
            _ciphertext[two] = c ^ subkey[subkey_start+2]
            _ciphertext[three] = d ^ subkey[subkey_start+3]
        
        return _ciphertext

    def decrypt(self, ciphertext, offset, length, subkey):
        _plaintext = ciphertext.copy()
        end = offset + length
        for i in range(0, end, self.BLOCK_LENGTH_LONGS):
            one = i + 1
            two = i + 2
            three = i + 3
            a = _plaintext[offset] ^ subkey[len(subkey)-4]
            b = _plaintext[one] ^ subkey[len(subkey)-3]
            c = _plaintext[two] ^ subkey[len(subkey)-2]
            d = _plaintext[three] ^ subkey[len(subkey)-1]
            temp = a + b

            for round_num in range(self.ROUND_NUM-1,-1,-1):
                a,b,c,d = self._round_decrypt(a,b,c,d,subkey,3+i*4)
            
            _plaintext[offset] = a
            _plaintext[one] = b
            _plaintext[two] = c
            _plaintext[three] = d
        
        return _plaintext