/*
 * Copyright (c) 1999-2001,2005-2007,2010-2012,2014 Apple Inc. All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * sslMemory.h - SSLBuffer and Memory allocator declarations
 */

/* This header should be kernel safe */

#ifndef _SSLMEMORY_H_
#define _SSLMEMORY_H_ 1

#include "sslTypes.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * General purpose allocators
 */
void *sslMalloc(size_t length);
void sslFree(void *p);

/*
 * SSLBuffer-oriented allocators
 */
int SSLAllocBuffer(SSLBuffer *buf, size_t length);
int SSLFreeBuffer(SSLBuffer *buf);

/*
 * Convenience routines
 */
uint8_t *sslAllocCopy(const uint8_t *src, size_t len);
int SSLCopyBufferFromData(
	const void *src,
	size_t len,
	SSLBuffer *dst);		// data mallocd and returned 
int SSLCopyBuffer(
	const SSLBuffer *src, 
	SSLBuffer *dst);		// data mallocd and returned

#ifdef __cplusplus
}
#endif

#define SET_SSL_BUFFER(buf, d, l)   do { (buf).data = (d); (buf).length = (l); } while (0)

#endif
