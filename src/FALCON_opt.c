#include <stdlib.h>
#include <stdio.h>
#include "FALCON_opt.h"
#include "Tables.h"

static const u64 Rc[21] = {
    0x243F6A8885A308D3, 0x13198A2E03707344, 0xA4093822299F31D0,
    0x082EFA98EC4E6C89, 0x452821E638D01377, 0xBE5466CF34E90C6C,
    0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917, 0x9216D5D98979FB1B,
    0xD1310BA698DFB5AC, 0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
    0xBA7C9045F12C7F99, 0x24A19947B3916CF7, 0x0801F2E2858EFC16,
    0x636920D871574E69, 0xA458FEA3F4933D7E, 0x0D95748F728EB658,
    0x718BCD5882154AEE, 0x7B54A41DC25A59B5, 0x9C30D5392AF26013,
};

#define ROTL(n, s) (((n) << s) | ((n) >> (64 - s)))
#define ROTR(n, s) (((n) >> s) | ((n) << (64 - s)))

// this macro is used only for the key expansion
#define MIX_WORDS(w0, w1, w2, w3) \
w1 = ROTL(w1, 8); \
w3 = ROTL(w3, 11); \
x0 = w0; \
x2 = w2; \
z0 = T0[w0 & 0xff] ^ T1[(w0 >> 8) & 0xff] ^ T2[(w0 >> 16) & 0xff] ^ T3[(w0 >> 24) & 0xff] ^ \
T4[(w0 >> 32) & 0xff] ^ T5[(w0 >> 40) & 0xff] ^ T6[(w0 >> 48) & 0xff] ^ T7[w0 >> 56]; \
\
z1 = T0[w2 & 0xff] ^ T1[(w2 >> 8) & 0xff] ^ T2[(w2 >> 16) & 0xff] ^ T3[(w2 >> 24) & 0xff] ^ \
T4[(w2 >> 32) & 0xff] ^ T5[(w2 >> 40) & 0xff] ^ T6[(w2 >> 48) & 0xff] ^ T7[w2 >> 56]; \
\
w0 = (w1 ^ z0) + z1; \
w2 = (w3 ^ z1) + z0; \
w1 = ROTL(w0, 29) ^ x0; \
w3 = ROTL(w2, 15) ^ x2; \

// performs one round of encryption with the specified round key
#define ENC_ROUND(k0, k1, k2, k3) \
w1 = ROTL(w1, 8); \
w3 = ROTL(w3, 11); \
x0 = w0; \
x2 = w2; \
z0 = T0[w0 & 0xff] ^ T1[(w0 >> 8) & 0xff] ^ T2[(w0 >> 16) & 0xff] ^ T3[(w0 >> 24) & 0xff] ^ \
T4[(w0 >> 32) & 0xff] ^ T5[(w0 >> 40) & 0xff] ^ T6[(w0 >> 48) & 0xff] ^ T7[w0 >> 56]; \
\
z1 = T0[w2 & 0xff] ^ T1[(w2 >> 8) & 0xff] ^ T2[(w2 >> 16) & 0xff] ^ T3[(w2 >> 24) & 0xff] ^ \
T4[(w2 >> 32) & 0xff] ^ T5[(w2 >> 40) & 0xff] ^ T6[(w2 >> 48) & 0xff] ^ T7[w2 >> 56]; \
\
w0 = ((w1 ^ z0) + z1) ^ rk[k0]; \
w2 = ((w3 ^ z1) + z0) ^ rk[k2]; \
w1 = (ROTL(w0 ^ rk[k0], 29) ^ x0) + rk[k1]; \
w3 = (ROTL(w2 ^ rk[k2], 15) ^ x2) + rk[k3]; \

#define R1  ENC_ROUND  (4, 5, 6, 7)
#define R2  ENC_ROUND  (8, 9, 10, 11)
#define R3  ENC_ROUND  (12, 13, 14, 15)
#define R4  ENC_ROUND  (16, 17, 18, 19)
#define R5  ENC_ROUND  (20, 21, 22, 23)
#define R6  ENC_ROUND  (24, 25, 26, 27)
#define R7  ENC_ROUND  (28, 29, 30, 31)
#define R8  ENC_ROUND  (32, 33, 34, 35)
#define R9  ENC_ROUND  (36, 37, 38, 39)
#define R10 ENC_ROUND  (40, 41, 42, 43)
#define R11 ENC_ROUND  (44, 45, 46, 47)
#define R12 ENC_ROUND  (48, 49, 50, 51)
#define R13 ENC_ROUND  (52, 53, 54, 55)
#define R14 ENC_ROUND  (56, 57, 58, 59)
#define R15 ENC_ROUND  (60, 61, 62, 63)
#define R16 ENC_ROUND  (64, 65, 66, 67)
#define R17 ENC_ROUND  (68, 69, 70, 71)
#define R18 ENC_ROUND  (72, 73, 74, 75)
#define R19 ENC_ROUND  (76, 77, 78, 79)
#define R20 ENC_ROUND  (80, 81, 82, 83)

// one round of decryption
#define DEC_ROUND(k0, k1, k2, k3) \
\
w1 -= rk[k1]; \
w3 -= rk[k3]; \
w0 = w1 ^ ROTL(w0 ^ rk[k0], 29); \
w2 = w3 ^ ROTL(w2 ^ rk[k2], 15); \
\
z0 = T0[w0 & 0xff] ^ T1[(w0 >> 8) & 0xff] ^ T2[(w0 >> 16) & 0xff] ^ T3[(w0 >> 24) & 0xff] ^ \
T4[(w0 >> 32) & 0xff] ^ T5[(w0 >> 40) & 0xff] ^ T6[(w0 >> 48) & 0xff] ^ T7[w0 >> 56]; \
\
z1 = T0[w2 & 0xff] ^ T1[(w2 >> 8) & 0xff] ^ T2[(w2 >> 16) & 0xff] ^ T3[(w2 >> 24) & 0xff] ^ \
T4[(w2 >> 32) & 0xff] ^ T5[(w2 >> 40) & 0xff] ^ T6[(w2 >> 48) & 0xff] ^ T7[w2 >> 56]; \
\
w1 = ROTR((ROTR(w1 ^ w0, 29) - z1) ^ z0, 8); \
w3 = ROTR((ROTR(w3 ^ w2, 15) - z0) ^ z1, 11); \


#define IR1  DEC_ROUND  (4, 5, 6, 7)
#define IR2  DEC_ROUND  (8, 9, 10, 11)
#define IR3  DEC_ROUND  (12, 13, 14, 15)
#define IR4  DEC_ROUND  (16, 17, 18, 19)
#define IR5  DEC_ROUND  (20, 21, 22, 23)
#define IR6  DEC_ROUND  (24, 25, 26, 27)
#define IR7  DEC_ROUND  (28, 29, 30, 31)
#define IR8  DEC_ROUND  (32, 33, 34, 35)
#define IR9  DEC_ROUND  (36, 37, 38, 39)
#define IR10 DEC_ROUND  (40, 41, 42, 43)
#define IR11 DEC_ROUND  (44, 45, 46, 47)
#define IR12 DEC_ROUND  (48, 49, 50, 51)
#define IR13 DEC_ROUND  (52, 53, 54, 55)
#define IR14 DEC_ROUND  (56, 57, 58, 59)
#define IR15 DEC_ROUND  (60, 61, 62, 63)
#define IR16 DEC_ROUND  (64, 65, 66, 67)
#define IR17 DEC_ROUND  (68, 69, 70, 71)
#define IR18 DEC_ROUND  (72, 73, 74, 75)
#define IR19 DEC_ROUND  (76, 77, 78, 79)
#define IR20 DEC_ROUND  (80, 81, 82, 83)


static u8 char_val(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    else if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    
    printf("Illegal character \"%c\" in key input string\n", c);
    exit(1);
    
    return 0;
}

int FALCON_KEY_INIT(u64 rk[/*4 * (NR + 1)*/], const void *input, const int format, const int keylen) {
    if (rk == NULL || input == NULL)
        return 1;
    if (keylen < 0 || keylen > 256)
        return 1;
    
    int i, j, bytes, bits;
    u8 state[64] = {};
    u64 *state_64 = (u64 *)state;
    u8 mk[32] = {};
    u64 x0, x2, z0, z1; // for the mixwords macro
    
    
    bytes = keylen / 8;
    bits = keylen % 8;
    
    for (i = 0; i < bytes; i++) {
        if (format == FORMAT_ASCII) {
            mk[i] = (char_val(((char *)input)[2 * i]) << 4) + char_val(((char *)input)[2 * i + 1]);
        } else {
            mk[i] = ((u8 *)input)[i];
        }
    }
    
    if (bits) { // parse any extra bits
        if (format == FORMAT_ASCII) {
            if (bits <= 4) {
                mk[bytes] = (char_val(((char *)input)[2 * bytes]) & ~(0x0fU >> bits)) << 4;
            } else {
                mk[bytes] = char_val(((char *)input)[2 * bytes]) << 4;
                mk[bytes] += char_val(((char *)input)[2 * bytes + 1]) & ~(0xf0U >> bits);
            }
        } else {
            mk[bytes] = ((u8 *)input)[bytes] & ~(0xffU >> bits);
        }
    }
    
    // initialize the state
    for (i = 0; i < bytes; i++) {
        state[i] = mk[i];
        state[i + 32] = 0xff;
    }
    
    for (j = 0; j < bits; j++) {
        state[bytes] ^= (0x80U >> j) & mk[bytes];
        state[bytes + 32] ^= (0x80U >> j);
    }
    
    // derive the round keys
    for (i = 0; i <= NR; i++) {
        rk[0] = state_64[0] ^ state_64[4] ^ Rc[i];
        rk[1] = state_64[1] ^ state_64[5];
        rk[2] = state_64[2] ^ state_64[6];
        rk[3] = state_64[3] ^ state_64[7];
        
        MIX_WORDS(rk[0], rk[1], rk[2], rk[3])
        
        state_64[0] = state_64[4];
        state_64[1] = state_64[5];
        state_64[2] = state_64[6];
        state_64[3] = state_64[7];
        state_64[4] = rk[0];
        state_64[5] = rk[1];
        state_64[6] = rk[2];
        state_64[7] = rk[3];
        
        rk += 4;
    }
    
    return 0;
}

void FALCON_ENC(const u8 pt[32], u8 ct[32], const u64 rk[/*4 * (NR + 1)*/]) {
    u64 *ct_64 = (u64 *)ct;
    u64 *pt_64 = (u64 *)pt;
    
    u64 w0, w1, w2, w3, x0, x2, z0, z1;
    
    //input whitening
    w0 = pt_64[0] ^ rk[0];
    w1 = pt_64[1] + rk[1];
    w2 = pt_64[2] ^ rk[2];
    w3 = pt_64[3] + rk[3];
    
#if NR > 0
    R1
#endif
#if NR > 1
    R2
#endif
#if NR > 2
    R3
#endif
#if NR > 3
    R4
#endif
#if NR > 4
    R5
#endif
#if NR > 5
    R6
#endif
#if NR > 6
    R7
#endif
#if NR > 7
    R8
#endif
#if NR > 8
    R9
#endif
#if NR > 9
    R10
#endif
#if NR > 10
    R11
#endif
#if NR > 11
    R12
#endif
#if NR > 12
    R13
#endif
#if NR > 13
    R14
#endif
#if NR > 14
    R15
#endif
#if NR > 15
    R16
#endif
#if NR > 16
    R17
#endif
#if NR > 17
    R18
#endif
#if NR > 18
    R19
#endif
#if NR > 19
    R20
#endif
    
    ct_64[0] = w0;
    ct_64[1] = w1;
    ct_64[2] = w2;
    ct_64[3] = w3;
}


void FALCON_DEC(const u8 ct[32], u8 pt[32], const u64 rk[/*4 * (NR + 1)*/]) {
    u64 *ct_64 = (u64 *)ct;
    u64 *pt_64 = (u64 *)pt;
    
    u64 w0, w1, w2, w3, z0, z1;
    w0 = ct_64[0];
    w1 = ct_64[1];
    w2 = ct_64[2];
    w3 = ct_64[3];
#if NR > 19
    IR20
#endif
#if NR > 18
    IR19
#endif
#if NR > 17
    IR18
#endif
#if NR > 16
    IR17
#endif
#if NR > 15
    IR16
#endif
#if NR > 14
    IR15
#endif
#if NR > 13
    IR14
#endif
#if NR > 12
    IR13
#endif
#if NR > 11
    IR12
#endif
#if NR > 10
    IR11
#endif
#if NR > 9
    IR10
#endif
#if NR > 8
    IR9
#endif
#if NR > 7
    IR8
#endif
#if NR > 6
    IR7
#endif
#if NR > 5
    IR6
#endif
#if NR > 4
    IR5
#endif
#if NR > 3
    IR4
#endif
#if NR > 2
    IR3
#endif
#if NR > 1
    IR2
#endif
#if NR > 0
    IR1
#endif
    
    // undo input whitening
    pt_64[0] = w0 ^ rk[0];
    pt_64[1] = w1 - rk[1];
    pt_64[2] = w2 ^ rk[2];
    pt_64[3] = w3 - rk[3];
    
}