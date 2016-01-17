#include <stdlib.h>
#include <stdio.h>
#include "FALCON_ref.h"

/* This file lets you test both encryption and decryption.
 Use the parse_ascii function to convert strings of hex to a corresponding array of bytes.
 */

int main(int argc, const char * argv[]) {
    u8 in[32] = {};
    u8 out[32] = {};
    u8 key[32] = {};
    const char mk[64] = "0000000000000000000000000000000000000000000000000000000000000000";
    int keylen = 256;
    
    parse_ascii(key, mk, keylen);
    
    //parse_ascii(in, "05d3f57aec2dc358feef14e004e6e2f38cfffa96cd2c9e7fd07afc5c859ae515", 256);
    
    FALCON_ENC(in, out, key, keylen);
    FALCON_DEC(out, in, key, keylen); // make sure decryption is working properly
    
    printf("Plaintext:  ");
    for (int i = 0; i < 32; i++)
        printf("%02x", in[i]);
    
    printf("\nKey:        ");
    for (int i = 0; i < keylen / 8 + (keylen % 8 != 0); i++)
        printf("%02x", key[i]);
    
    printf("\nCiphertext: ");
    for (int i = 0; i < 32; i++)
        printf("%02x", out[i]);
    
    printf("\n");
    
    return 0;
}
