#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "skein.h"
#include "threefish.h"

void print_bytes(uint8_t *bytes, uint16_t byteslen) {
    int i;
    for (i=0; i<byteslen; i++) {
        printf("%02x", bytes[i]);
    }
}

void print_words(uint64_t *words, uint16_t wordslen) {
    int i;
    for (i=0; i<wordslen; i++) {
        printf("%llx", words[i]);
    }
}

int main ()
{
    int i;
    uint8_t msg[128];
    uint8_t hashval[64];
    uint64_t plainwords[8];
    uint64_t result[8];
    Skein_Ctxt_t ctx;

    Threefish_Ctxt_t cipher_ctx;

    for (i=0; i<8; i++) {
        cipher_ctx.key[i] = i*2;
        plainwords[i] = i;
    }
    //memset(cipher_ctx.key, 0, 64);
    memset(cipher_ctx.tweak, 0, 16);
    //memset(plainwords, 0, 64);
    Threefish_prep(&cipher_ctx);
    Threefish_encrypt(&cipher_ctx, plainwords, result, 0);

    print_words(result, 8);
    printf ("\n\n");
    

    Skein_Init(&ctx, 512, NULL, 0);
    for (i=0; i<128; i++) {
        msg[i] = 255-i;
    }
    Skein_Update(&ctx, msg, 64);
    Skein_Final(&ctx, hashval, 1);
    
    print_bytes(hashval, 64);
    printf ("\n");



    return (0);
}

