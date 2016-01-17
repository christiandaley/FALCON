#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "FALCON_opt.h"
#include "rijndael-alg-fst.h"

#define MB (2000ull) // number of MB of data to encrypt. Setting this too low may not give accurate results.
#define TRIALS 2 // number of trials to run for encrytion
#define FALCON_BLOCK_SIZE 32
#define RIJNDAEL_BLOCK_SIZE 16
#define KEY_SETUP_ITER 50000000 // number of iterations to run for key setup test

/* freqeuncy of the processor. Uncomment and set this value to the
correct value for your machine in order to see more information about the speeds */

//#define CLOCK_FREQ (2.6e9)

void print_info(const double time, const u64 blocks, const char *cipher_name, const int nr) {
    printf("-------------------------------------------------\n");
    printf("%s (%d rounds) encrypted %llu MB of data in %2lf seconds.\n", cipher_name, nr, MB, time);
    printf("%lf MB/s             %lf blocks/second\n", MB / time, blocks / time);
#ifdef CLOCK_FREQ
    printf("%lf cycles/block     %lf cycles/byte\n", time * CLOCK_FREQ / blocks, time * CLOCK_FREQ / MB / 1e6);
#endif
    printf("-------------------------------------------------\n");
}

double test_rijndael(const int keysize) {
    if (keysize != 128 && keysize != 192 && keysize != 256)
        return 0;
    clock_t start, end;
    int i, nr;
    u64 blocks = MB * 1e6 / RIJNDAEL_BLOCK_SIZE;
    blocks >>= 1;
    u32 rk[60];
    u8 mk[32];
    u8 a[16], b[16];
    
    start = clock();
    nr = rijndaelKeySetupDec(rk, mk, keysize);
    for (i = 0; i < blocks; i++) {
        rijndaelEncrypt(rk, nr, a, b);
        rijndaelEncrypt(rk, nr, b, a);
    }
    
    end = clock();
    return ((double)end - (double)start) / (double)CLOCKS_PER_SEC;
}

double test_falcon() {
    clock_t start, end;
    int i;
    u64 blocks = MB * 1e6 / FALCON_BLOCK_SIZE;
    blocks >>= 1;
    
    u8 mk[32], a[32], b[32];
    u64 rk[84];
    start = clock();
    
    FALCON_KEY_INIT(rk, mk, FORMAT_RAW, 256);
    for (i = 0; i < blocks; i++) {
        FALCON_ENC(a, b, rk);
        FALCON_ENC(b, a, rk);
    }
    
    end = clock();
    
    return ((double)end - (double)start) / (double)CLOCKS_PER_SEC;
}

void test_enc_speed() {
    double falcon = 0, aes_128 = 0, aes_192 = 0, aes_256 = 0;
    double t;
    int i;
    for (i = 0; i < TRIALS; i++) {
        printf("\nTrial #%d: encrypting %llu MB of data...\n", i + 1, MB);
        // AES-128
        t = test_rijndael(128);
        aes_128 += t;
        print_info(t, MB * 1e6 / RIJNDAEL_BLOCK_SIZE, "AES-128", 10);
        
        // AES-192
        t = test_rijndael(192);
        aes_192 += t;
        print_info(t, MB * 1e6 / RIJNDAEL_BLOCK_SIZE, "AES-192", 12);
        
        // AES-256
        t = test_rijndael(256);
        aes_256 += t;
        print_info(t, MB * 1e6 / RIJNDAEL_BLOCK_SIZE, "AES-256", 14);
        
        // NR round FALCON
        t = test_falcon();
        print_info(t, MB * 1e6 / FALCON_BLOCK_SIZE, "FALCON", NR);
        falcon += t;
    }
    
#if TRIALS > 1
    aes_128 /= TRIALS;
    aes_192 /=TRIALS;
    aes_256 /= TRIALS;
    falcon /= TRIALS;
    printf("\n\n-----AVERAGE RESULTS-----\n");
    print_info(aes_128, MB * 1e6 / RIJNDAEL_BLOCK_SIZE, "AES-128", 10);
    print_info(aes_192, MB * 1e6 / RIJNDAEL_BLOCK_SIZE, "AES-192", 12);
    print_info(aes_256, MB * 1e6 / RIJNDAEL_BLOCK_SIZE, "AES-256", 14);
    print_info(falcon, MB * 1e6 / FALCON_BLOCK_SIZE, "FALCON", NR);
#endif
    
}

void test_key_speed() {
    clock_t start, end;
    u64 f_key[84];
    u32 aes_rk[60];
    u8 mk[32];
    int i;
    double t;
    printf("\n--------Testing key setup times: %d trials--------\n\n", KEY_SETUP_ITER);
    
    // AES-128
    start = clock();
    for (i = 0; i < KEY_SETUP_ITER; i++)
        rijndaelKeySetupEnc(aes_rk, mk, 128);
    
    end = clock();
    t = ((double)end - (double)start) / CLOCKS_PER_SEC / KEY_SETUP_ITER;
    
    printf("AES-128 average key setup time: %lf nanoseconds\n", t * 1e9);
#ifdef CLOCK_FREQ
    printf("%lf cycles               %lf cycles/byte\n\n", CLOCK_FREQ * t, CLOCK_FREQ * t / (RIJNDAEL_BLOCK_SIZE * 11));
#endif
    
    // AES-192
    start = clock();
    for (i = 0; i < KEY_SETUP_ITER; i++)
        rijndaelKeySetupEnc(aes_rk, mk, 192);
    
    end = clock();
    t = ((double)end - (double)start) / CLOCKS_PER_SEC / KEY_SETUP_ITER;
    
    printf("AES-192 average key setup time: %lf nanoseconds\n", t * 1e9);
#ifdef CLOCK_FREQ
    printf("%lf cycles               %lf cycles/byte\n\n", CLOCK_FREQ * t, CLOCK_FREQ * t / (RIJNDAEL_BLOCK_SIZE * 13));
#endif
    // AES-256
    start = clock();
    for (i = 0; i < KEY_SETUP_ITER; i++)
        rijndaelKeySetupEnc(aes_rk, mk, 256);
    
    end = clock();
    t = ((double)end - (double)start) / CLOCKS_PER_SEC / KEY_SETUP_ITER;
    
    printf("AES-256 average key setup time: %lf nanoseconds\n", t * 1e9);
#ifdef CLOCK_FREQ
    printf("%lf cycles               %lf cycles/byte\n\n", CLOCK_FREQ * t, CLOCK_FREQ * t / (RIJNDAEL_BLOCK_SIZE * 15));
#endif
    // FALCON
    start = clock();
    for (i = 0; i < KEY_SETUP_ITER; i++)
        FALCON_KEY_INIT(f_key, mk, FORMAT_RAW, 256);
    
    end = clock();
    t = ((double)end - (double)start) / CLOCKS_PER_SEC / KEY_SETUP_ITER;
    
    printf("%d-round FALCON average key setup time: %lf nanoseconds\n", NR, t * 1e9);
#ifdef CLOCK_FREQ
    printf("%lf cycles               %lf cycles/byte\n\n", CLOCK_FREQ * t, CLOCK_FREQ * t / (FALCON_BLOCK_SIZE * (NR + 1)));
#endif
    
    
}

int main(int argc, const char * argv[]) {
    test_enc_speed();
    test_key_speed();
    
    return 0;
}
