#include <stdio.h>
#include <stdlib.h>
#include "FALCON_ref.h"

// same S-box that Rijndael uses
static const u8 sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

/* round constants used by the key schedule.
 The hexadecimal representation of pi */

static const u64 Rc[21] = {
    0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0,
    0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917, 0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16,
    0x636920D871574E69, 0xA458FEA3F4933D7E, 0x0D95748F728EB658,
    0x718BCD5882154AEE, 0x7B54A41DC25A59B5, 0x9C30D5392AF26013,
};

// the 8x8 matrix used in F to provide diffusion
static const u8 mds_matrix[8][8] = {
    {1, 3, 4, 5, 6, 8, 11, 7},
    {3, 1, 5, 4, 8, 6, 7, 11},
    {4, 5, 1, 3, 11, 7, 6, 8},
    {5, 4, 3, 1, 7, 11, 8, 6},
    {6, 8, 11, 7, 1, 3, 4, 5},
    {8, 6, 7, 11, 3, 1, 5, 4},
    {11, 7, 6, 8, 4, 5, 1, 3},
    {7, 11, 8, 6, 5, 4, 3, 1}
};

static u8 round_keys[32 * (NR + 1)]; // the round keys.
static u64 *rk_64; // rk_64 will end up pointing to the same data as round_keys


#define ROTL(n, s) (((n) << s) | ((n) >> (64 - s)))
#define ROTR(n, s) (((n) >> s) | ((n) << (64 - s)))

#define MULT_X(n) ((n) & 0x80 ? ((n) << 1) ^ 0x1b : ((n) << 1))

// multiplication x * y in GF(2^8) (Rijndael's finite field)

static u8 gf_mult(u8 x, u8 y) {
    u8 result = 0;
    
    while (x != 0) {
        result ^= x & 1 ? y : 0;
        x >>= 1;
        y = MULT_X(y);
    }
    
    return result;
}

/* "F" function. It takes a 64-bit word as an input, passes the individual bytes through Rijndael's S-box,
 and then multiplies them by an 8x8 mds matrix.
 */

static u64 F(u64 x) {
    
    u8 *temp = (u8 *)&x;
    u8 a[8] = {};
    int i, j;
    // replace each byte by its corresponding S-box entry
    for (i = 0; i < 8; i++)
        temp[i] = sbox[temp[i]];
    
    // multiply by 8x8 matrix
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 8; j++) {
            a[i] ^= gf_mult(temp[j], mds_matrix[i][j]);
        }
    }
    
    x = *((u64 *)a);
    
    return x;
}

// MixWords takes four 64-bit words as an input and returns four 64-bit words as an output.
static void mix_words(u64 *w0, u64 *w1, u64 *w2, u64 *w3) {
    u64 z0, z1, a0, a1, a2, a3; // temporary variables
    a0 = *w0; a1 = *w1;
    a2 = *w2; a3 = *w3;
    
    a1 = ROTL(a1, 8);
    a3 = ROTL(a3, 11);
    
    z0 = F(a0);
    z1 = F(a2);
    
    *w0 = (a1 ^ z0) + z1;
    *w2 = (a3 ^ z1) + z0;
    
    *w1 = a0 ^ ROTL(*w0, 29);
    *w3 = a2 ^ ROTL(*w2, 15);
}

// inverse of MixWords.

static void inv_mix_words(u64 *w0, u64 *w1, u64 *w2, u64 *w3) {
    u64 z0, z1, a0, a1, a2, a3;
    a0 = *w0; a1 = *w1;
    a2 = *w2; a3 = *w3;
    
    *w0 = ROTL(a0, 29) ^ a1;
    *w2 = ROTL(a2, 15) ^ a3;
    
    z0 = F(*w0);
    z1 = F(*w2);
    
    *w1 = ROTR((a0 - z1) ^ z0, 8);
    *w3 = ROTR((a2 - z0) ^ z1, 11);
    
}

// generates all of the subkeys needed for every round of the cipher.
static void key_schedule(u8 *mk, int keylen) {
    if (keylen < 0 || keylen > 256) {
        printf("Invalid key size\n");
        exit(1);
    }
    
    u8 state[64] = {};
    u64 *state_64 = (u64 *)state;
    rk_64 = (u64 *)round_keys;
    int i, j;
    int bytes = keylen / 8; // number of whole bytes in the master key
    int bits = keylen % 8; // number of "extra bits" after the last whole byte
    
    // initialize the state and the padding
    for (i = 0; i < bytes; i++) {
        state[i] = mk[i];
        state[i + 32] = 0xff;
    }
    
    // finish initializing the state and padding if there are extra bits to be processed
    for (j = 0; j < bits; j++) {
        state[bytes] ^= (0x80U >> j) & mk[i];
        state[bytes + 32] ^= (0x80U >> j);
    }
    
    // derive all of the round keys
    for (i = 0; i <= NR; i++) {
        rk_64[0] = state_64[0] ^ state_64[4] ^ Rc[i];
        rk_64[1] = state_64[1] ^ state_64[5];
        rk_64[2] = state_64[2] ^ state_64[6];
        rk_64[3] = state_64[3] ^ state_64[7];
        
        mix_words(rk_64, rk_64 + 1, rk_64 + 2, rk_64 + 3);
        
        state_64[0] = state_64[4];
        state_64[1] = state_64[5];
        state_64[2] = state_64[6];
        state_64[3] = state_64[7];
        
        state_64[4] = rk_64[0];
        state_64[5] = rk_64[1];
        state_64[6] = rk_64[2];
        state_64[7] = rk_64[3];
        
        rk_64 += 4;
    }
    
    rk_64 = (u64 *)round_keys;
}

// applies the key to the data. dir indicates encryption or decryption
static void apply_round_key(u8 *data, int round, int dir) {
    u64 *temp = (u64 *)data;
    
    temp[0] ^= rk_64[round * 4];
    temp[2] ^= rk_64[2 + round * 4];
    
    if (dir == 0) {
        temp[1] += rk_64[1 + round * 4];
        temp[3] += rk_64[3 + round * 4];
    } else {
        temp[1] -= rk_64[1 + round * 4];
        temp[3] -= rk_64[3 + round * 4];
    }
}

// encryption
void FALCON_ENC(const u8 pt[32], u8 ct[32], u8 *key, int keylen) {
    key_schedule(key, keylen);
    int i, round;
    
    for (i = 0; i < 32; i++)
        ct[i] = pt[i];
    
    for (round = 0; round < NR; round++) {
        apply_round_key(ct, round, 0); // when round == 0 this results in input whitening
        
        mix_words((u64 *)ct, (u64 *)ct + 1, (u64 *)ct + 2, (u64 *)ct + 3);
        
    }
    
    apply_round_key(ct, NR, 0); // output whitening
    
}

// encryption
void FALCON_DEC(const u8 ct[32], u8 pt[32], u8 *key, int keylen) {
    key_schedule(key, keylen);
    
    int i, round;
    
    for (i = 0; i < 32; i++)
        pt[i] = ct[i];
    
    apply_round_key(pt, NR, 1); // undo output whitening
    
    for (round = NR - 1; round >= 0; round--) {
        inv_mix_words((u64 *)pt, (u64 *)pt + 1, (u64 *)pt + 2, (u64 *)pt + 3);
        apply_round_key(pt, round, 1);
    }
}


// returns the value of an ascii character interpreted in hexadecimal
static u8 char_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    
    printf("Illegal character \"%c\"\n", c);
    exit(1);
    
    return 0;
}


// utility parsing function.
void parse_ascii(u8 *data, const char *ascii, int len) {
    if (len < 0 || len > 256) {
        printf("Invalid key size\n");
        exit(1);
    }
    
    int bytes = len / 8;
    int bits = len % 8;
    
    int i;
    for (i = 0; i < bytes; i++)
        data[i] = (char_val(ascii[i * 2]) << 4) + char_val(ascii[i * 2 + 1]);
    
     // are there "extra" bits that need to be parsed?
    if (bits) {
        if (bits <= 4) {
            data[bytes] = (char_val(ascii[bytes * 2]) & ~(0x0fU >> bits)) << 4;
        } else {
            data[bytes] = char_val(ascii[bytes * 2]) << 4;
            data[bytes] += char_val(ascii[bytes * 2 + 1]) & ~(0xf0U >> bits);
        }
    }
    
}