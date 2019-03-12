/*
The C reference implementation of the
block cipher family XCRUSH.
This software is released into the public domain.
*/
#include <stdio.h>
#define BLOCK_LENGTH_LONGS 4
#define KEY_LEN_128_BITS 2
#define KEY_LEN_192_BITS 3
#define KEY_LEN_256_BITS 4
#define NUM_SUBKEYS 16
#define C 4142135623730950488L
#define LONG_LONG_SIZE 64

int compress(unsigned long long x) {
    x = (x >> 32) + x;
    x = (x >> 11) ^ x;
    x = (x >> 9) + x;
    return ((x >> 6) + x) & 0x3f;
}

long long avalanche(unsigned long long v, unsigned long long a) {
    v += a;
    const int shiftAmount = compress(a);
    /* ROTATE LEFT */
    return (v << shiftAmount) | (v >> (LONG_LONG_SIZE - shiftAmount));
}

long long unavalanche(unsigned long long v, unsigned long long a) {
    const int shiftAmount = compress(a);
    /* ROTATE RIGHT */
    v = (v >> shiftAmount) | (v << (LONG_LONG_SIZE - shiftAmount));
    return v - a;
}

void _encrypt(unsigned long long plaintext[], int offset, int length, unsigned long long subkeys[16]) {
    const long __0 = subkeys[0];
    const long __1 = subkeys[1];
    const long __2 = subkeys[2];
    const long __3 = subkeys[3];
    const long __4 = subkeys[4];
    const long __5 = subkeys[5];
    const long __6 = subkeys[6];
    const long __7 = subkeys[7];
    const long __8 = subkeys[8];
    const long __9 = subkeys[9];
    const long _10 = subkeys[10];
    const long _11 = subkeys[11];
    const long _12 = subkeys[12];
    const long _13 = subkeys[13];
    const long _14 = subkeys[14];
    const long _15 = subkeys[15];
    const int end = offset + length;
    int one___, two___, three_;
    long a_, b_, c_, d_, temp;

    // for each block
    for ( ; offset < end; offset += BLOCK_LENGTH_LONGS) {
        one___ = offset + 1;
        two___ = offset + 2;
        three_ = offset + 3;
        a_ = plaintext[offset];
        b_ = plaintext[one___];
        c_ = plaintext[two___];
        d_ = plaintext[three_];

        /* round 1 */
        temp = c_ + d_;
        a_ = avalanche(a_, temp + b_ + __0);
        b_ = avalanche(b_, temp + a_ + __1);
        temp = a_ + b_;
        c_ = avalanche(c_, temp + d_ + __2);
        d_ = avalanche(d_, temp + c_ + __3);

        /* round 2 */
        temp = c_ + d_;
        a_ = avalanche(a_, temp + b_ + __4);
        b_ = avalanche(b_, temp + a_ + __5);
        temp = a_ + b_;
        c_ = avalanche(c_, temp + d_ + __6);
        d_ = avalanche(d_, temp + c_ + __7);

        /* round 3 */
        temp = c_ + d_;
        a_ = avalanche(a_, temp + b_ + __8);
        b_ = avalanche(b_, temp + a_ + __9);
        temp = a_ + b_;
        c_ = avalanche(c_, temp + d_ + _10);
        d_ = avalanche(d_, temp + c_ + _11);
        
        plaintext[offset] = a_ ^ _12;
        plaintext[one___] = b_ ^ _13;
        plaintext[two___] = c_ ^ _14;
        plaintext[three_] = d_ ^ _15;
    }
}

void decrypt(unsigned long long ciphertext[], int offset, int length, unsigned long long subkeys[16]) {
    const long __0 = subkeys[0];
    const long __1 = subkeys[1];
    const long __2 = subkeys[2];
    const long __3 = subkeys[3];
    const long __4 = subkeys[4];
    const long __5 = subkeys[5];
    const long __6 = subkeys[6];
    const long __7 = subkeys[7];
    const long __8 = subkeys[8];
    const long __9 = subkeys[9];
    const long _10 = subkeys[10];
    const long _11 = subkeys[11];
    const long _12 = subkeys[12];
    const long _13 = subkeys[13];
    const long _14 = subkeys[14];
    const long _15 = subkeys[15];
    const int end = offset + length;
    int one___, two___, three_;
    long a_, b_, c_, d_, temp;
    for ( ; offset < end; offset += BLOCK_LENGTH_LONGS) {
        one___ = offset + 1;
        two___ = offset + 2;
        three_ = offset + 3;
        a_ = ciphertext[offset] ^ _12;
        b_ = ciphertext[one___] ^ _13;
        c_ = ciphertext[two___] ^ _14;
        d_ = ciphertext[three_] ^ _15;
        temp = a_ + b_;
        d_ = unavalanche(d_, temp + c_ + _11);
        c_ = unavalanche(c_, temp + d_ + _10);
        temp = c_ + d_;
        b_ = unavalanche(b_, temp + a_ + __9);
        a_ = unavalanche(a_, temp + b_ + __8);
        temp = a_ + b_;
        d_ = unavalanche(d_, temp + c_ + __7);
        c_ = unavalanche(c_, temp + d_ + __6);
        temp = c_ + d_;
        b_ = unavalanche(b_, temp + a_ + __5);
        a_ = unavalanche(a_, temp + b_ + __4);
        temp = a_ + b_;
        d_ = unavalanche(d_, temp + c_ + __3);
        c_ = unavalanche(c_, temp + d_ + __2);
        temp = c_ + d_;
        b_ = unavalanche(b_, temp + a_ + __1);
        a_ = unavalanche(a_, temp + b_ + __0);
        ciphertext[offset] = a_;
        ciphertext[one___] = b_;
        ciphertext[two___] = c_;
        ciphertext[three_] = d_;
    }
}

long long S_1, S_2, S_3, S_4, S_5;

long long next() {
    long long t = S_2;
    S_2 = S_3;
    S_3 = S_4;
    S_4 = S_5;
    S_5 = S_1;
    S_1 = avalanche(S_1, S_1 + t);
    return S_1;
}

void expand_key(unsigned long long key[], int keyLen, unsigned long long subkeybuf[NUM_SUBKEYS]) {
    switch (keyLen) {
        case KEY_LEN_128_BITS:
            S_1 = key[0];
            S_2 = key[1];
            S_3 = C;
            S_4 = C;
            S_5 = C;
            break;
        case KEY_LEN_192_BITS:
            S_1 = key[0];
            S_2 = key[1];
            S_3 = key[2];
            S_4 = C;
            S_5 = C;
            break;
        case KEY_LEN_256_BITS:
            S_1 = key[0];
            S_2 = key[1];
            S_3 = key[2];
            S_4 = key[3];
            S_5 = C;
            break;
        default:
            break;
    }

    for(int i = 0; i < 10; i++) {
        next();
    }

    for(int i = 0; i < NUM_SUBKEYS; i++) {
        subkeybuf[i] = next();
    }
}

int main(int argc, const char * argv[]) {
    const int keyLen = KEY_LEN_256_BITS;
    unsigned long long key[keyLen] = {
    0xF0E0D0C0B0A09080L,
    0x7060504030201000L,
    0xF1D3B597795B3D1FL,
    0x021346578A9BCEDFL
    };

    const int dataLen = 4;
    unsigned long long data[dataLen] = {
    0x311d411620304361L,
    0x48165c7790022614L,
    0x9536295b87012640L,
    0x396218842a490866L
    };

    unsigned long long subkeys[NUM_SUBKEYS];
    expand_key(key, keyLen, subkeys);

    for(int i = 0; i < dataLen; i++) {
        printf("%#llx ", data[i]);
    }
    
    printf("\n");
    _encrypt(data, 0, dataLen, subkeys);
    
    for(int i = 0; i < dataLen; i++) {
        printf("%#llx ", data[i]);
    }
    
    printf("\n");
    decrypt(data, 0, dataLen, subkeys);
    
    for(int i = 0; i < dataLen; i++) {
        printf("%#llx ", data[i]);
    };

    return 0;
}