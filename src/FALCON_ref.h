#ifndef FALCON_ref_h
#define FALCON_ref_h

#define NR 16 // number of rounds. Dont set this higher than 20.

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

/* encrypts "pt" with "key" and stores the result in "ct". "pt" and "ct" mut both be 32 bytes
 in length, and the keylen must be between 0 and 256 */
void FALCON_ENC(const u8 pt[32], u8 ct[32], u8 *key, int keylen);

// decryption
void FALCON_DEC(const u8 ct[32], u8 pt[32], u8 *key, int keylen);

/* utility function for parsing ascii into actual bytes of data.
len is given in bits, must be between 0 and 256, inclusively */
void parse_ascii(u8 *data, const char *ascii, int len);

#endif /* FALCON_ref_h */
