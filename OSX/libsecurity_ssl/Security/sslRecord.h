/*
 * Copyright (c) 2000-2001,2005-2007,2010-2012,2014 Apple Inc. All Rights Reserved.
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
 * sslRecord.h - SSL Record Layer
 */

#ifndef _SSLRECORD_H_
#define _SSLRECORD_H_ 1

#include "sslPriv.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Slightly smaller that 16384 to make room for a MAC in an SSL 2.0 
 * 3-byte header record 
 */
#define MAX_RECORD_LENGTH   16300

OSStatus SSLWriteRecord(
    SSLRecord 	rec,
    SSLContext 	*ctx);

OSStatus SSLFreeRecord(
    SSLRecord 	rec,
    SSLContext 	*ctx);

OSStatus SSLReadRecord(
	SSLRecord 	*rec,
	SSLContext 	*ctx);

OSStatus SSLServiceWriteQueue(
    SSLContext  *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _SSLRECORD_H_ */
