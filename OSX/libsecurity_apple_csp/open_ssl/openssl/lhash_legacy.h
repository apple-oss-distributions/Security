/*
 * Copyright (c) 2000-2001,2011,2014 Apple Inc. All Rights Reserved.
 * 
 * The contents of this file constitute Original Code as defined in and are
 * subject to the Apple Public Source License Version 1.2 (the 'License').
 * You may not use this file except in compliance with the License. Please obtain
 * a copy of the License at http://www.apple.com/publicsource and read it before
 * using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS
 * OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. Please see the License for the
 * specific language governing rights and limitations under the License.
 */


/* crypto/lhash/lhash_legacy.h */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

/* Header for dynamic hash table routines
 * Author - Eric Young
 */

#ifndef HEADER_LHASH_H
#define HEADER_LHASH_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef NO_FP_API
#include <stdio.h>
#endif

typedef struct lhash_node_st
	{
	void *data;
	struct lhash_node_st *next;
#ifndef NO_HASH_COMP
	unsigned long hash;
#endif
	} LHASH_NODE;

typedef int (*LHASH_COMP_FN_TYPE) (const void *, const void *);
typedef unsigned long (*LHASH_HASH_FN_TYPE) (const void *);
typedef void (*LHASH_DOALL_FN_TYPE) (void *);
typedef void (*LHASH_DOALL_ARG_FN_TYPE) (void *, void *);

typedef struct lhash_st
	{
	LHASH_NODE **b;
	LHASH_COMP_FN_TYPE comp;
	LHASH_HASH_FN_TYPE hash;
	unsigned int num_nodes;
	unsigned int num_alloc_nodes;
	unsigned int p;
	unsigned int pmax;
	unsigned long up_load; /* load times 256 */
	unsigned long down_load; /* load times 256 */
	unsigned long num_items;

	unsigned long num_expands;
	unsigned long num_expand_reallocs;
	unsigned long num_contracts;
	unsigned long num_contract_reallocs;
	unsigned long num_hash_calls;
	unsigned long num_comp_calls;
	unsigned long num_insert;
	unsigned long num_replace;
	unsigned long num_delete;
	unsigned long num_no_delete;
	unsigned long num_retrieve;
	unsigned long num_retrieve_miss;
	unsigned long num_hash_comps;

	int error;
	} LHASH;

#define LH_LOAD_MULT	256

/* Indicates a malloc() error in the last call, this is only bad
 * in lh_insert(). */
#define lh_error(lh)	((lh)->error)

LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c);
void lh_free(LHASH *lh);
void *lh_insert(LHASH *lh, void *data);
void *lh_delete(LHASH *lh, void *data);
void *lh_retrieve(LHASH *lh, void *data);
void lh_doall(LHASH *lh, LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func,void *arg);
unsigned long lh_strhash(const char *c);
unsigned long lh_num_items(LHASH *lh);

#ifndef NO_FP_API
void lh_stats(LHASH *lh, FILE *out);
void lh_node_stats(LHASH *lh, FILE *out);
void lh_node_usage_stats(LHASH *lh, FILE *out);
#endif

#ifdef HEADER_BIO_H
void lh_stats_bio(LHASH *lh, BIO *out);
void lh_node_stats_bio(LHASH *lh, BIO *out);
void lh_node_usage_stats_bio(LHASH *lh, BIO *out);
#endif
#ifdef  __cplusplus
}
#endif

#endif

