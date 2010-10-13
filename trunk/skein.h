/*
    skein.h
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

#ifndef _SKEIN_H_
#define _SKEIN_H_     1

#include <stdint.h>
#include "threefish.h"

typedef struct                           
    {
    uint32_t  hashBitLen;
    uint32_t  bCnt;
    Threefish_Ctxt_t TF;
    uint8_t   b[64];
    } Skein_Ctxt_t;

void  Skein_Process_Block(Skein_Ctxt_t *ctx,const uint8_t *blkPtr,uint32_t blkCnt,uint32_t byteCntAdd);

void  Skein_Init(Skein_Ctxt_t *ctx, uint32_t hashBitLen, const uint8_t *key, uint32_t keyBytes);

void  Skein_Update(Skein_Ctxt_t *ctx, const uint8_t *msg, uint32_t msgByteCnt);

void  Skein_Final (Skein_Ctxt_t *ctx, uint8_t * hashVal, int output);

uint32_t Skein_Output(Skein_Ctxt_t *ctx, uint8_t *hashVal, uint32_t byteCnt, uint32_t loopStart);

void Skein_Rand_Seed(Skein_Ctxt_t *ctx, uint8_t *seed, uint32_t seedBytes);
void Skein_Rand(Skein_Ctxt_t *ctx, uint32_t requestBytes, uint8_t *out);

/* "Internal" Skein definitions */
#define KEY        (0)
#define NONCE      ((uint64_t) 21 << 58)
#define MSG        ((uint64_t) 7 << 60)
#define CFG_FINAL  ((uint64_t) 49 << 58)
#define OUT_FINAL  ((uint64_t) 255 << 56)

#define SKEIN_VERSION           (1)

#ifndef SKEIN_ID_STRING_LE      /* allow compile-time personalization */
#define SKEIN_ID_STRING_LE      (0x33414853)            /* "SHA3" (little-endian)*/
#endif

#define SKEIN_MK_64(hi32,lo32)  ((lo32) + (((uint64_t) (hi32)) << 32))
#define SKEIN_SCHEMA_VER        SKEIN_MK_64(SKEIN_VERSION,SKEIN_ID_STRING_LE)
#define SKEIN_KS_PARITY         SKEIN_MK_64(0x55555555,0x55555555)

#endif  /* ifndef _SKEIN_H_ */
