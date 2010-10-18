/*
    threefish.c
    Copyright 2010 Jonathan Bowman

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at
  
        http://www.apache.org/licenses/LICENSE-2.0
  
    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
    implied. See the License for the specific language governing
    permissions and limitations under the License.
*/

#include <string.h>
#include <stdio.h>
#include "threefish.h"
#include "skein.h"

uint8_t ROT[] = {46, 36, 19, 37,
                 33, 27, 14, 42,
                 17, 49, 36, 39,
                 44,  9, 54, 56,
                 39, 30, 34, 24,
                 13, 50, 10, 17,
                 25, 29, 39, 43,
                  8, 35, 56, 22};

uint8_t PERM[] = {0,1,2,3,4,5,6,7,
                  2,1,4,7,6,5,0,3,
                  4,1,6,3,0,5,2,7,
                  6,1,0,7,2,5,4,3};

#if     BIGENDIAN
uint64_t ByteSwap64(uint64_t words) {
    return  (( words       & 0xFF) << 56) |
            (((words >> 8) & 0xFF) << 48) |
            (((words >>16) & 0xFF) << 40) |
            (((words >>24) & 0xFF) << 32) |
            (((words >>32) & 0xFF) << 24) |
            (((words >>40) & 0xFF) << 16) |
            (((words >>48) & 0xFF) <<  8) |
            (((words >>56) & 0xFF)      ) ;
}

void     words2bytes(uint8_t *dst,const uint64_t *src, uint16_t length) {
    uint16_t n;

    for (n=0;n<length;n++)
        dst[n] = (uint8_t) (src[n>>3] >> (8*(n&7)));
}

void     bytes2words(uint64_t *dst,const uint8_t *src, uint16_t length) {
    uint16_t n;

    for (n=0;n<8*length;n+=8)
        dst[n/8] = (((uint64_t) src[n  ])      ) +
                   (((uint64_t) src[n+1]) <<  8) +
                   (((uint64_t) src[n+2]) << 16) +
                   (((uint64_t) src[n+3]) << 24) +
                   (((uint64_t) src[n+4]) << 32) +
                   (((uint64_t) src[n+5]) << 40) +
                   (((uint64_t) src[n+6]) << 48) +
                   (((uint64_t) src[n+7]) << 56) ;
    }
#endif
/* 64-bit rotate left */
uint64_t RotL_64(uint64_t x, uint16_t N) {
  return (x << (N & 63)) | (x >> ((64-N) & 63));
}

/* 64-bit rotate right */
uint64_t RotR_64(uint64_t x, uint16_t N) {
  return (x >> (N & 63)) | (x << ((64-N) & 63));
}

void Threefish_prep(Threefish_Ctxt_t *ctx) {
    ctx->key[8] = ctx->key[0] ^ ctx->key[1] ^ ctx->key[2] ^ ctx->key[3] ^ 
                  ctx->key[4] ^ ctx->key[5] ^ ctx->key[6] ^ ctx->key[7] ^ SKEIN_KS_PARITY;
    ctx->tweak[2] = ctx->tweak[0] ^ ctx->tweak[1];
}

void Threefish_encrypt(Threefish_Ctxt_t *ctx, const uint64_t *p, uint64_t *out, int feed) {
    uint64_t X[8];
    int8_t i,m,n,r,s,y;

    for(i=0;i<8;i++) {
        X[i] = p[i] + ctx->key[i];
    }
    X[5] += ctx->tweak[0];
    X[6] += ctx->tweak[1];

    /* The rounds: */
    for (r=1, s=0; r<=18; r++, s^=16) {
        for (i=0; i<16; i++) {
            m = PERM[2*i];
            n = PERM[2*i+1];
            X[m] += X[n]; X[n] = RotL_64(X[n], ROT[i+s]); X[n] ^= X[m];
        }
        for (y=0;y<8;y++)
            X[y] += ctx->key[(r+y) % 9];
        X[5] += ctx->tweak[r % 3];
        X[6] += ctx->tweak[(r+1) % 3];
        X[7] += r;
    }

    if (feed) {
        for (i=0; i<8; i++) {
            out[i] = X[i] ^ p[i];
        }
    } else {
        memcpy(out, X, 64);
    }
}

void Threefish_decrypt(Threefish_Ctxt_t *ctx, const uint64_t *c, uint64_t *out) {
    uint64_t X[8];
    int8_t i,m,n,r,s,y;

    memcpy(X, c, 64);

    /* The rounds: */
    for (r=18, s=16; r>=1; r--, s^=16) {
        for (y=0;y<8;y++) {
            X[y] -= ctx->key[(r+y) % 9];
        }
        X[5] -= ctx->tweak[(r) % 3];
        X[6] -= ctx->tweak[(r+1) % 3];
        X[7] -= r;

        for (i=15; i>=0; i--) {
            m = PERM[2*i];
            n = PERM[2*i+1];
            X[n] = RotR_64(X[m]^X[n], ROT[i+s]); X[m] -= X[n];
        }
    }

    for (i=0; i<8; i++) {
        out[i] = X[i] - ctx->key[i];
    }
    out[5] -= ctx->tweak[0];
    out[6] -= ctx->tweak[1];
}
