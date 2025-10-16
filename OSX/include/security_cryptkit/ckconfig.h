/*
	File:		ckconfig.h

	Contains:	Common config info.


	Copyright:	Copyright (c) 1998,2011,2014 Apple Inc.
                All rights reserved.

	Change History (most recent first):

	<7>	10/06/98	ap		Changed to compile with C++.

	To Do:
*/

/* Copyright (c) 1998,2011,2014 Apple Inc.  All Rights Reserved.
 *
 * NOTICE: USE OF THE MATERIALS ACCOMPANYING THIS NOTICE IS SUBJECT
 * TO THE TERMS OF THE SIGNED "FAST ELLIPTIC ENCRYPTION (FEE) REFERENCE
 * SOURCE CODE EVALUATION AGREEMENT" BETWEEN APPLE, INC. AND THE
 * ORIGINAL LICENSEE THAT OBTAINED THESE MATERIALS FROM APPLE,
 * INC.  ANY USE OF THESE MATERIALS NOT PERMITTED BY SUCH AGREEMENT WILL
 * EXPOSE YOU TO LIABILITY.
 ***************************************************************************
 */

#ifndef	_CK_CONFIG_H_
#define _CK_CONFIG_H_

/*
 * Common build flags.
 */
#define DEBUG_ENGINE	0

/*
 * These CK_*_BUILD options used to control feature flags for different build strategies.  As we
 * only build in Security.framework (AppleCSP) these days, code not needed for this use case has been removed.
 * For posterity, the feature flags of CK_SECURITY_BUILD will be described below.
 */
 
#ifdef	CK_SECURITY_BUILD
/* 
 * Standard Security.framework build
 
#define CRYPTKIT_DER_ENABLE        1           // DER encoding support
#define CRYPTKIT_LIBMD_DIGEST        1         // use CommonCrypto digests
#define CRYPTKIT_ELL_PROJ_ENABLE    1          // elliptic projection
#define CRYPTKIT_ECDSA_ENABLE        1         // ECDSA (requires ELL_PROJ_ENABLE)
#define CRYPTKIT_CIPHERFILE_ENABLE  0          // cipherfile w/symmetric encryption
#define CRYPTKIT_SYMMETRIC_ENABLE   0          // symmetric encryption
#define CRYPTKIT_ASYMMETRIC_ENABLE  1          // asymmetric encryption
#define CRYPTKIT_MD5_ENABLE        1           // MD5 hash
#define CRYPTKIT_SHA1_ENABLE        1          // SHA1 hash - needed for GHMAX_LEGACY
#define CRYPTKIT_HMAC_LEGACY        1
#define CRYPTKIT_KEY_EXCHANGE        0         // FEE key exchange
#define CRYPTKIT_HIGH_LEVEL_SIG        0       // high level one-shot signature
#define CRYPTKIT_GIANT_STACK_ENABLE 0          // cache of giants
 */

#else

#error You must supply a build configuration. 
#endif

#endif	/* _CK_CONFIG_H_ */
