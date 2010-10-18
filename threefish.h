/*
    threefish.h
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


#ifndef _THREEFISH_H_
#define _THREEFISH_H_     1

#include <stdint.h>

typedef struct                           
    {
    uint8_t ROT[32];
    uint8_t PERM[32];
    uint64_t key[9];
    uint64_t tweak[3];
    } Threefish_Ctxt_t;


void Threefish_init(Threefish_Ctxt_t *ctx);
void Threefish_prep(Threefish_Ctxt_t *ctx);
void Threefish_encrypt(Threefish_Ctxt_t *ctx, const uint64_t *p, uint64_t *out, int feed);
void Threefish_decrypt(Threefish_Ctxt_t *ctx, const uint64_t *c, uint64_t *out);

uint64_t RotL_64(uint64_t x, uint16_t N);
uint64_t RotR_64(uint64_t x, uint16_t N);

#if     BIGENDIAN
uint64_t ByteSwap64(uint64_t words);
void     words2bytes(uint8_t *dst,const uint64_t *src, uint16_t length);
void     bytes2words(uint64_t *dst,const uint8_t *src, uint16_t length);
#else
#define ByteSwap64(words)  (words)
#define words2bytes(dst08,src64,bCnt) memcpy(dst08,src64,bCnt)
#define bytes2words(dst64,src08,wCnt) memcpy(dst64,src08,8*(wCnt))
#endif
#endif  /* ifndef _THREEFISH_H_ */