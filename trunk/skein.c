/*
    skein.c
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

#include <string.h>      /* get the memcpy/memset functions */
#include <stdio.h>
#include "skein.h"

void Skein_Start_New_Type(Skein_Ctxt_t *ctx, uint64_t type) {
  ctx->bCnt = 0;
  ctx->TF.tweak[0] = 0;
  ctx->TF.tweak[1] = type;
}

/*****************************************************************/
/* External function to process blkCnt (nonzero) full block(s) of data. */
void Skein_Process_Block(Skein_Ctxt_t *ctx,const uint8_t *blkPtr,uint32_t blkCnt,uint32_t byteCntAdd)
    {
    uint64_t  w[8];                           /* local copy of input block */
    do  {
        ctx->TF.tweak[0] += byteCntAdd;                /* update processed length */

        memcpy(w,blkPtr,64); /* copy input block */

        Threefish_prep(&ctx->TF);

        Threefish_encrypt(&ctx->TF, w, ctx->TF.key, 1);
        
        ctx->TF.tweak[1] &= ((uint64_t) 3 << 62)-1; /* 0xbfffffffffffffff (~SKEIN_T1_FLAG_FIRST) */
        blkPtr += 64;
        }
    while (--blkCnt);
    }

/*****************************************************************/
/*     512-bit Skein                                             */
/*****************************************************************/

void Skein_Rand_Seed(Skein_Ctxt_t *ctx, uint8_t *seed, uint32_t seedBytes) {
  uint8_t state[64];
  if (ctx->bCnt == 0) {
    memset(state,0,64);        /* no existing state; set chaining vars to zero */
    Threefish_init(&ctx->TF);
  } else {
    memcpy(state, ctx->TF.key, 64);
  }
  ctx->hashBitLen=512;     /* set output hash bit count = state size */
  Skein_Start_New_Type(ctx,NONCE);
  Skein_Update(ctx, state,64);     /* hash the previous state */
  Skein_Update(ctx,seed,seedBytes);     /* add the seed */
  Skein_Final(ctx, state, 1);
  memcpy(ctx->TF.key,state,64);   /* new state */
}

void Skein_Rand(Skein_Ctxt_t *ctx, uint32_t requestBytes, uint8_t *out) {
  uint8_t state[64];
  memcpy(state, ctx->TF.key, 64);
  ctx->hashBitLen=512 + requestBytes * 8;     /* set output hash bit count = state size + bytes requested */
  Skein_Start_New_Type(ctx,NONCE);
  Skein_Update(ctx, state, 64);     /* hash the previous state */
  Skein_Final(ctx, NULL, 0);
  Skein_Output(ctx, state, 64, 0);
  Skein_Output(ctx, out, requestBytes, 1);
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* init the context for a hashing operation  */
void Skein_Init(Skein_Ctxt_t *ctx, uint32_t hashBitLen, const uint8_t *key, uint32_t keyBytes)
    {
    union
        {
        uint8_t  b[64];
        uint64_t  w[8];
        } cfg;                              /* config block */
        
    Threefish_init(&ctx->TF);

    /* compute the initial chaining values ctx->TF.key[], based on key */
    if (keyBytes == 0)                          /* is there a key? */
        {                                   
        memset(ctx->TF.key,0,64);        /* no key: use all zeroes as key for config block */
        }
    else                                        /* here to pre-process a key */
        {
        /* do a mini-Init right here */
        ctx->hashBitLen=512;     /* set output hash bit count = state size */
        
        Skein_Start_New_Type(ctx,KEY); /* Set new tweak for key derivation */

        memset(ctx->TF.key,0,64);        /* zero the initial chaining variables */
        Skein_Update(ctx,key,keyBytes);     /* hash the key */
        Skein_Final(ctx,cfg.b,0);         /* put result into cfg.b[] */
        memcpy(ctx->TF.key,cfg.b,64);     /* copy over into ctx->TF.key[] */
        }
    /* build/process the config block, type == CONFIG (could be precomputed for each key) */
    ctx->hashBitLen = hashBitLen;             /* output hash bit count */

    Skein_Start_New_Type(ctx,CFG_FINAL); // Set new tweak for final configuration

    memset(&cfg.w,0,64);             /* pre-pad cfg.w[] with zeroes */
    cfg.w[0] = SKEIN_SCHEMA_VER; // 0x7f3bfc5
    cfg.w[1] = hashBitLen;        /* hash result length in bits */
    //cfg.w[2] = 0;  /* I don't need tree hashing */

    /* compute the initial chaining values from config block */
    Skein_Process_Block(ctx,cfg.b,1,32); /* 32 is SKEIN_CFG_STR_LEN */

    /* The chaining vars ctx->TF.key are now initialized */
    /* Set up to process the data message portion of the hash (default) */

    Skein_Start_New_Type(ctx,MSG); // Set new tweak for message processing
    }

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process the input bytes */
void Skein_Update(Skein_Ctxt_t *ctx, const uint8_t *msg, uint32_t msgByteCnt)
    {
    uint32_t n;

    /* process full blocks, if any */
    if (msgByteCnt + ctx->bCnt > 64)
        {
        if (ctx->bCnt)                              /* finish up any buffered message data */
            {
            n = 64 - ctx->bCnt;  /* # bytes free in buffer b[] */
            if (n)
                {
                memcpy(&ctx->b[ctx->bCnt],msg,n);
                msgByteCnt  -= n;
                msg         += n;
                ctx->bCnt += n;
                }
            Skein_Process_Block(ctx,ctx->b,1,64);
            ctx->bCnt = 0;
            }
        /* now process any remaining full blocks, directly from input message data */
        if (msgByteCnt > 64)
            {
            n = (msgByteCnt-1) / 64;   /* number of full blocks to process */
            Skein_Process_Block(ctx,msg,n,64);
            msgByteCnt -= n * 64;
            msg        += n * 64;
            }
        }

    /* copy any remaining source message data bytes into b[] */
    if (msgByteCnt)
        {
        memcpy(&ctx->b[ctx->bCnt],msg,msgByteCnt);
        ctx->bCnt += msgByteCnt;
        }
    }
   
/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the result */
void Skein_Final(Skein_Ctxt_t *ctx, uint8_t *hashVal, int output) {
    /*
    uint32_t i,n,byteCnt;
    uint64_t X[8];
    */

    ctx->TF.tweak[1] |= ((uint64_t) 1 << 63); /* SKEIN_T1_FLAG_FINAL (tag as the final block) */
    if (ctx->bCnt < 64)            /* zero pad b[] if necessary */
        memset(&ctx->b[ctx->bCnt],0,64 - ctx->bCnt);

    Skein_Process_Block(ctx,ctx->b,1,ctx->bCnt);  /* process the final block */
    
    if (hashVal) {
      if (output) {
        Skein_Output(ctx, hashVal, 0, 0);
      } else {
        memcpy(hashVal,ctx->TF.key,64);   /* "output" the state bytes */
      }
    }
}

uint32_t Skein_Output(Skein_Ctxt_t *ctx, uint8_t *hashVal, uint32_t byteCnt, uint32_t loopStart) {
  uint32_t i, n;
  uint64_t X[8];

  if (!byteCnt) {
    byteCnt = (ctx->hashBitLen + 7) >> 3;             /* total number of output bytes */
  }/* else {
    byteCnt = byteCnt + loopStart * 64;
  }
  printf("%lu\n", byteCnt);
  */


  /* run Threefish in "counter mode" to generate output */
  memset(ctx->b,0,64);  /* zero out b[], so it can hold the counter */
  memcpy(X,ctx->TF.key,64);       /* keep a local copy of counter mode "key" */
  for (i=0;i*64 < byteCnt;i++) {
    ((uint64_t *)ctx->b)[0] = ((uint64_t) i + loopStart); /* build the counter block */
    
    Skein_Start_New_Type(ctx,OUT_FINAL); // Set new tweak for final output

    Skein_Process_Block(ctx,ctx->b,1,sizeof(uint64_t)); /* run "counter mode" */
    n = byteCnt - i*64;   /* number of output bytes left to go */
    if (n >= 64)
        n  = 64;
    memcpy(hashVal+i*64,ctx->TF.key,n);   /* "output" the ctr mode bytes */
    memcpy(ctx->TF.key,X,64);   /* restore the counter mode key for next time */
  }
  return (i + loopStart);
}
