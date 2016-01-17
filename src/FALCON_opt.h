#ifndef FALCON_opt_h
#define FALCON_opt_h

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned long long u64;

#define NR 16 // Number of rounds. Recommended is 16. Maximum is 20.
#define FORMAT_RAW 0
#define FORMAT_ASCII 1
#define BYTES_PER_BLOCK 32

// rk needs be of length 4 * (NR + 1)
// returns 0 if successful, 1 otherwise. The key expansion is stored in rk
int FALCON_KEY_INIT(u64 rk[/*4 * (NR + 1)*/], const void *input, const int format, const int keylen);

void FALCON_ENC(const u8 pt[32], u8 ct[32], const u64 rk[/*4 * (NR + 1)*/]);
void FALCON_DEC(const u8 ct[32], u8 pt[32], const u64 rk[/*4 * (NR + 1)*/]);

#endif /* FALCON_opt_h */