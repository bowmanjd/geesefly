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

void Threefish_init(Threefish_Ctxt_t *ctx) {
    uint32_t *PERM = (uint32_t *) ctx->PERM;
    uint32_t *ROT = (uint32_t *) ctx->ROT;
    PERM[0] = 0x3020100;
    PERM[1] = 0x7060504;
    PERM[2] = 0x7040102;
    PERM[3] = 0x3000506;
    PERM[4] = 0x3060104;
    PERM[5] = 0x7020500;
    PERM[6] = 0x7000106;
    PERM[7] = 0x3040502;
    ROT[0] = 0x2513242e;
    ROT[1] = 0x2a0e1b21;
    ROT[2] = 0x27243111;
    ROT[3] = 0x3836092c;
    ROT[4] = 0x18221e27;
    ROT[5] = 0x110a320d;
    ROT[6] = 0x2b271d19;
    ROT[7] = 0x16382308;
}

void Threefish_encrypt(Threefish_Ctxt_t *ctx, const uint64_t *p, uint64_t *out, int feed)
{
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
        m = ctx->PERM[2*i];
        n = ctx->PERM[2*i+1];
        X[m] += X[n]; X[n] = RotL_64(X[n], ctx->ROT[i+s]); X[n] ^= X[m];
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

void Threefish_decrypt(Threefish_Ctxt_t *ctx, const uint64_t *c, uint64_t *out)
{
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
        m = ctx->PERM[2*i];
        n = ctx->PERM[2*i+1];
        X[n] = RotR_64(X[m]^X[n], ctx->ROT[i+s]); X[m] -= X[n];
      }
    }

    for (i=0; i<8; i++) {
      out[i] = X[i] - ctx->key[i];
    }
    out[5] -= ctx->tweak[0];
    out[6] -= ctx->tweak[1];
}
