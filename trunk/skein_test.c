#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "skein.h"
#include "threefish.h"

void hexprint(uint8_t *bytes, uint16_t byteslen) {
    int i;
    for (i=0; i<byteslen; i++) {
        printf("%02x", bytes[i]);
    }
}

int main ()
{
    int i;
    uint8_t msg[128];
    uint8_t hashval[64];
    Skein_Ctxt_t ctx;

    //Threefish_Ctxt_t cipher_ctx;
    

    Skein_Init(&ctx, 512, NULL, 0);
    for (i=0; i<128; i++) {
        msg[i] = 255-i;
    }
    Skein_Update(&ctx, msg, 64);
    Skein_Final(&ctx, hashval, 1);
    
    hexprint(hashval, 64);
    printf ("\n");



    return (0);
}

