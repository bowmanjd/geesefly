/*
 * skein.c
 * Copyright 2010 Jonathan Bowman
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * 	http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
*/

#include <string.h>
#include <stdio.h>
#include "skein_endian.h"
#include "skein.h"

void skein_new_type(struct skein_ctx *ctx, uint64_t type)
{
	ctx->b_cnt = 0;
	ctx->tf.tweak[0] = 0;
	ctx->tf.tweak[1] = type;
}

void skein_process_block(struct skein_ctx *ctx, const uint8_t *blk_ptr,
				uint32_t blk_cnt, uint32_t byte_len)
{
	uint64_t w[8];
	do {
		ctx->tf.tweak[0] += byte_len;
		bytes2words(w,blk_ptr,8);
		tf_prep(&ctx->tf);
		tf_encrypt(&ctx->tf, w, ctx->tf.key, 1);
		ctx->tf.tweak[1] &= 0xbfffffffffffffffULL;
		blk_ptr += 64;
	} while (--blk_cnt);
}

void skein_rand_seed(struct skein_ctx *ctx, uint8_t *seed, uint32_t seed_bytes)
{
	uint8_t state[64];
	if (ctx->b_cnt == 0) {
		memset(state,0,64);
	} else {
		memcpy(state, ctx->tf.key, 64);
	}
	ctx->digest_bits=512;
	skein_new_type(ctx,NONCE);
	skein_update(ctx, state,64);  /* hash the previous state */
	skein_update(ctx,seed,seed_bytes);  /* add the seed */
	skein_final(ctx, state, 1);
	memcpy(ctx->tf.key,state,64);  /* new state */
}

void skein_rand(struct skein_ctx *ctx, uint32_t request_bytes, uint8_t *out)
{
	uint8_t state[64];
	memcpy(state, ctx->tf.key, 64);
	ctx->digest_bits=512 + request_bytes * 8;
	skein_new_type(ctx,NONCE);
	skein_update(ctx, state, 64);  /* hash the previous state */
	skein_final(ctx, NULL, 0);
	skein_output(ctx, state, 64, 0);
	skein_output(ctx, out, request_bytes, 1);
}

/* init the context for a hashing operation  */
void skein_init(struct skein_ctx *ctx, uint32_t digest_bits,
			const uint8_t *key, uint32_t key_len)
{
	union {
		uint8_t  b[64];
		uint64_t  w[8];
	} cfg;  /* config block */
		
	/* compute the initial chaining values
	 * ctx->tf.key[], based on key */
	if (key_len == 0) {
		/* no key: use all zeroes as key for config block */
		memset(ctx->tf.key,0,64);
	} else {  /* here to pre-process a key */
		/* do a mini-Init right here */
		ctx->digest_bits=512;
		
		skein_new_type(ctx,KEY); /* Set new tweak for key derivation */

		memset(ctx->tf.key,0,64);		/* zero the initial chaining variables */
		skein_update(ctx,key,key_len);	 /* hash the key */
		skein_final(ctx,cfg.b,0);		 /* put result into cfg.b[] */
		bytes2words(ctx->tf.key,cfg.b,64);	 /* copy over into ctx->tf.key[] */
	}
	/* build/process the config block, type == CONFIG (could be precomputed for each key) */
	ctx->digest_bits = digest_bits;			 /* output hash bit count */

	skein_new_type(ctx,CFG_FINAL); // Set new tweak for final configuration

	memset(&cfg.w,0,64);			 /* pre-pad cfg.w[] with zeroes */
	cfg.w[0] = ByteSwap64(SKEIN_SCHEMA_VER); // 0x7f3bfc5
	cfg.w[1] = ByteSwap64(digest_bits);		/* hash result length in bits */

	/* compute the initial chaining values from config block */
	skein_process_block(ctx,cfg.b,1,32);

	/* The chaining vars ctx->tf.key are now initialized */
	/* Set up to process the data message portion of the hash (default) */

	skein_new_type(ctx,MSG); // Set new tweak for message processing
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* process the input bytes */
void skein_update(struct skein_ctx *ctx, const uint8_t *msg,
					uint32_t msg_len)
{
	uint32_t n;

	/* process full blocks, if any */
	if (msg_len + ctx->b_cnt > 64) {
		if (ctx->b_cnt) {  /* finish up any buffered message data */
			n = 64 - ctx->b_cnt;  /* # bytes free in buffer b[] */
			if (n) {
				memcpy(&ctx->b[ctx->b_cnt],msg,n);
				msg_len  -= n;
				msg		 += n;
				ctx->b_cnt += n;
			}
			skein_process_block(ctx,ctx->b,1,64);
			ctx->b_cnt = 0;
		}
		/* now process any remaining full blocks, directly from input message data */
		if (msg_len > 64) {
			n = (msg_len-1) / 64;   /* number of full blocks to process */
			skein_process_block(ctx,msg,n,64);
			msg_len -= n * 64;
			msg		+= n * 64;
		}
	}

	/* copy any remaining source message data bytes into b[] */
	if (msg_len) {
		memcpy(&ctx->b[ctx->b_cnt],msg,msg_len);
		ctx->b_cnt += msg_len;
	}
}

/*++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/* finalize the hash computation and output the result */
void skein_final(struct skein_ctx *ctx, uint8_t *result, int output)
{
	ctx->tf.tweak[1] |= ((uint64_t) 1 << 63); /* SKEIN_T1_FLAG_FINAL (tag as the final block) */
	if (ctx->b_cnt < 64)			/* zero pad b[] if necessary */
		memset(&ctx->b[ctx->b_cnt],0,64 - ctx->b_cnt);

	skein_process_block(ctx,ctx->b,1,ctx->b_cnt);  /* process the final block */
	
	if (result) {
	  if (output) {
		skein_output(ctx, result, 0, 0);
	  } else {
		words2bytes(result,ctx->tf.key,64);   /* "output" the state bytes */
	  }
	}
}

uint32_t skein_output(struct skein_ctx *ctx, uint8_t *result,
			uint32_t digest_size, uint32_t count)
{
	uint32_t i, n;
	uint64_t state[8];

	if (!digest_size) {
		digest_size = (ctx->digest_bits + 7) >> 3;  /* total number of output bytes */
	}

	/* run Threefish in "counter mode" to generate output */
	memset(ctx->b,0,64);  /* zero out b[], so it can hold the counter */
	memcpy(state,ctx->tf.key,64);  /* keep a local copy of counter mode "key" */
	for (i=0;i*64 < digest_size;i++) {
		((uint64_t *)ctx->b)[0] = ByteSwap64((uint64_t) i + count); /* build the counter block */
		
		skein_new_type(ctx,OUT_FINAL); // Set new tweak for final output

		skein_process_block(ctx,ctx->b,1,sizeof(uint64_t)); /* run "counter mode" */
		n = digest_size - i*64;   /* number of output bytes left to go */
		if (n >= 64)
			n  = 64;
		words2bytes(result+i*64,ctx->tf.key,n);   /* "output" the ctr mode bytes */
		memcpy(ctx->tf.key,state,64);   /* restore the counter mode key for next time */
	}
	return (i + count);
}
