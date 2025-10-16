/*
 * Copyright (c) 2009-2010,2012 Apple Inc. All Rights Reserved.
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
 *
 * oidsocsp.h -- Object Identifiers for OCSP
 */

#ifndef _OIDSOCSP_H_
#define _OIDSOCSP_H_  1

#include <Security/SecAsn1Types.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const SecAsn1Oid
	/* OCSP */
	OID_PKIX_OCSP SEC_ASN1_API_DEPRECATED,
	OID_PKIX_OCSP_BASIC SEC_ASN1_API_DEPRECATED,
	OID_PKIX_OCSP_NONCE SEC_ASN1_API_DEPRECATED,
	OID_PKIX_OCSP_CRL SEC_ASN1_API_DEPRECATED,
	OID_PKIX_OCSP_RESPONSE SEC_ASN1_API_DEPRECATED,
	OID_PKIX_OCSP_NOCHECK SEC_ASN1_API_DEPRECATED,
	OID_PKIX_OCSP_ARCHIVE_CUTOFF SEC_ASN1_API_DEPRECATED,
    OID_PKIX_OCSP_SERVICE_LOCATOR SEC_ASN1_API_DEPRECATED,
    OID_GOOGLE_OCSP_SCT SEC_ASN1_API_DEPRECATED;

#ifdef __cplusplus
}
#endif

#endif /* _OIDSOCSP_H_ */
