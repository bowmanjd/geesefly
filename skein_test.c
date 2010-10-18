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
        printf("0x%llx,", words[i]);
    }
}

void test_threefish_words_only() {
    int i;
    Threefish_Ctxt_t ctx;
    uint64_t plainwords[8];
    uint64_t result[8];
    uint64_t correct_result[8] = {0x9a5423dc987b345cLLU,
                                  0x789b6615397cfd5dLLU,
                                  0xddf015ca531fc2aeLLU,
                                  0x558006fab5dd908fLLU,
                                  0x95d6ad8aebb8ff78LLU,
                                  0xc480b2cefc006a36LLU,
                                  0x05445e06242ebddaLLU,
                                  0x4a88dcd9c901a298LLU};

    for (i=0; i<8; i++) {
        ctx.key[i] = i*2;
        plainwords[i] = i;
    }
    memset(ctx.tweak, 0, 16);
    Threefish_prep(&ctx);
    Threefish_encrypt(&ctx, plainwords, result, 0);

    printf("Testing endian agnostic Threefish...\t");
    if(memcmp(result, correct_result, 64) == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILURE\nresult: ");
        print_words(result, 8);
        printf ("\n");
    }
}

void test_skein_vectors() {
    int i;
    Skein_Ctxt_t ctx;
    uint8_t msg[128];
    uint8_t result[64];
    uint8_t correct_result1[64] = {
        0x42, 0xaa, 0x6b, 0xd9, 0xca, 0x92, 0xe9, 0x0e,
        0xa2, 0x8d, 0xf6, 0xf6, 0xf2, 0xd0, 0xd9, 0xb8,
        0x5a, 0x2d, 0x19, 0x07, 0xee, 0x4d, 0xc1, 0xb1,
        0x71, 0xac, 0xe7, 0xeb, 0x11, 0x59, 0xbe, 0x3b,
        0xd1, 0xbc, 0x56, 0x58, 0x6d, 0x92, 0x49, 0x2b,
        0x6e, 0xff, 0x9b, 0xe0, 0x33, 0x06, 0x99, 0x4c,
        0x65, 0xa3, 0x32, 0xc4, 0xc2, 0x41, 0x60, 0xf4,
        0x66, 0x55, 0x04, 0x0e, 0x55, 0x8e, 0x83, 0x29
    };
    uint8_t correct_result2[64] = {
        0x04, 0xf9, 0x6c, 0x6f, 0x61, 0xb3, 0xe2, 0x37,
        0xa4, 0xfa, 0x77, 0x55, 0xee, 0x4a, 0xcf, 0x34,
        0x49, 0x42, 0x22, 0x96, 0x89, 0x54, 0xf4, 0x95,
        0xad, 0x14, 0x7a, 0x1a, 0x71, 0x5f, 0x7a, 0x73,
        0xeb, 0xec, 0xfa, 0x1e, 0xf2, 0x75, 0xbe, 0xd8,
        0x7d, 0xc6, 0x0b, 0xd1, 0xa0, 0xbc, 0x60, 0x21,
        0x06, 0xfa, 0x98, 0xf8, 0xe7, 0x23, 0x7b, 0xd1,
        0xac, 0x09, 0x58, 0xe7, 0x6d, 0x30, 0x66, 0x78
    };
    uint8_t correct_result3[64] = {
        0xb4, 0x84, 0xae, 0x9f, 0xb7, 0x3e, 0x66, 0x20,
        0xb1, 0x0d, 0x52, 0xe4, 0x92, 0x60, 0xad, 0x26,
        0x62, 0x0d, 0xb2, 0x88, 0x3e, 0xba, 0xfa, 0x21,
        0x0d, 0x70, 0x19, 0x22, 0xac, 0xa8, 0x53, 0x68,
        0x08, 0x81, 0x44, 0xbd, 0xf4, 0xef, 0x3d, 0x98,
        0x98, 0xd4, 0x7c, 0x34, 0xf1, 0x30, 0x03, 0x1b,
        0x0a, 0x09, 0x92, 0xf0, 0x9f, 0x62, 0xdd, 0x78,
        0xb3, 0x29, 0x52, 0x5a, 0x77, 0x7d, 0xaf, 0x7d
    };

    for (i=0; i<128; i++) {
        msg[i] = 255-i;
    }

    Skein_Init(&ctx, 512, NULL, 0);
    Skein_Update(&ctx, msg, 1);
    Skein_Final(&ctx, result, 1);
    printf("Testing Skein one-byte test vector...\t");
    if(memcmp(result, correct_result1, 64) == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILURE\nresult: ");
        print_bytes(result, 64);
        printf("\n");
    }
    
    Skein_Init(&ctx, 512, NULL, 0);
    Skein_Update(&ctx, msg, 64);
    Skein_Final(&ctx, result, 1);
    printf("Testing Skein 64-byte test vector...\t");
    if(memcmp(result, correct_result2, 64) == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILURE\nresult: ");
        print_bytes(result, 64);
        printf("\n");
    }

    Skein_Init(&ctx, 512, NULL, 0);
    Skein_Update(&ctx, msg, 128);
    Skein_Final(&ctx, result, 1);
    printf("Testing Skein 128-byte test vector...\t");
    if(memcmp(result, correct_result3, 64) == 0) {
        printf("SUCCESS\n");
    } else {
        printf("FAILURE\nresult: ");
        print_bytes(result, 64);
        printf("\n");
    }
}

int main ()
{
    test_threefish_words_only();
    test_skein_vectors();
    
    return (0);
}

