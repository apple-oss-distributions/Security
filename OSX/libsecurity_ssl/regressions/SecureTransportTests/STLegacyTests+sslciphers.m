/*
 * Copyright (c) 2012,2014 Apple Inc. All Rights Reserved.
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


#include <stdio.h>
#include <stdlib.h>
#include <Security/SecureTransportPriv.h>
#include <AssertMacros.h>
#include <utilities/SecCFRelease.h>

#include "ssl-utils.h"

#include "cipherSpecs.h"
#import "STLegacyTests.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"

@implementation STLegacyTests (sslciphers)

static int test_GetSupportedCiphers(SSLContextRef ssl, bool server)
{
    size_t max_ciphers = 0;
    int fail=1;
    SSLCipherSuite *ciphers = NULL;

    require_noerr(SSLGetNumberSupportedCiphers(ssl, &max_ciphers), out);

    size_t size = max_ciphers * sizeof (SSLCipherSuite);
    ciphers = (SSLCipherSuite *) malloc(size);

    require_string(ciphers, out, "out of memory");
    memset(ciphers, 0xff, size);

    size_t num_ciphers = max_ciphers;
    require_noerr(SSLGetSupportedCiphers(ssl, ciphers, &num_ciphers), out);

    for (size_t i = 0; i < num_ciphers; i++) {
        require(ciphers[i]!=(SSLCipherSuite)(-1), out);
    }

    /* Success! */
    fail=0;

out:
    if(ciphers) free(ciphers);
    return fail;
}


static OSStatus SocketWrite(SSLConnectionRef conn, const void *data, size_t *length)
{
    return errSSLWouldBlock;
}

static OSStatus SocketRead(SSLConnectionRef conn, void *data, size_t *length)
{
    return errSSLWouldBlock;
}



static const SSLCipherSuite legacy_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
};

const SSLCipherSuite legacy_DHE_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
    SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
};



const SSLCipherSuite standard_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
};

const SSLCipherSuite default_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
};

const SSLCipherSuite ATSv1_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
};

const SSLCipherSuite ATSv1_noPFS_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,

    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
};

const SSLCipherSuite TLSv1_RC4_fallback_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
};

const SSLCipherSuite TLSv1_fallback_ciphersuites[] = {
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA256,
    TLS_RSA_WITH_AES_128_CBC_SHA256,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    SSL_RSA_WITH_3DES_EDE_CBC_SHA,
};

const SSLCipherSuite anonymous_ciphersuites[] = {
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA,
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256,
    TLS_DH_anon_WITH_AES_256_CBC_SHA,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256,
    TLS_DH_anon_WITH_AES_128_CBC_SHA
};


static int test_GetEnabledCiphers(SSLContextRef ssl, unsigned expected_num_ciphers, const SSLCipherSuite *expected_ciphers)
{
    size_t num_ciphers;
    size_t size;
    int fail=1;
    SSLCipherSuite *ciphers = NULL;

    require_noerr(SSLSetIOFuncs(ssl, &SocketRead, &SocketWrite), out);
    require_noerr(SSLSetConnection(ssl, NULL), out);

    require_noerr(SSLGetNumberEnabledCiphers(ssl, &num_ciphers), out);
    require_string(num_ciphers==expected_num_ciphers, out, "wrong ciphersuites number");

    size = num_ciphers * sizeof (SSLCipherSuite);
    ciphers = (SSLCipherSuite *) malloc(size);
    require_string(ciphers, out, "out of memory");
    memset(ciphers, 0xff, size);

    require_noerr(SSLGetEnabledCiphers(ssl, ciphers, &num_ciphers), out);
    require_string(memcmp(ciphers, expected_ciphers, size)==0, out, "wrong ciphersuites");

    free(ciphers);
    ciphers = NULL;

    require(SSLHandshake(ssl) == errSSLWouldBlock, out);

    require_noerr(SSLGetNumberEnabledCiphers(ssl, &num_ciphers), out);
    require_string(num_ciphers==expected_num_ciphers, out, "wrong ciphersuites number");

    size = num_ciphers * sizeof (SSLCipherSuite);
    ciphers = (SSLCipherSuite *) malloc(size);
    require_string(ciphers, out, "out of memory");
    memset(ciphers, 0xff, size);

    require_noerr(SSLGetEnabledCiphers(ssl, ciphers, &num_ciphers), out);
    require_string(memcmp(ciphers, expected_ciphers, size)==0, out, "wrong ciphersuites");

    /* Success! */
    fail=0;

out:
    free(ciphers);
    return fail;
}

static int test_SetEnabledCiphers(SSLContextRef ssl)
{
    int fail=1;
    size_t num_enabled;
    
    /* This should not fail as long as we have one valid cipher in this table */
    SSLCipherSuite ciphers[] = {
        SSL_RSA_WITH_RC2_CBC_MD5, /* unsupported */
        TLS_RSA_WITH_NULL_SHA, /* supported by not enabled by default */
        TLS_RSA_WITH_AES_128_CBC_SHA, /* Supported and enabled by default */
    };

    require_noerr(SSLSetEnabledCiphers(ssl, ciphers, sizeof(ciphers)/sizeof(SSLCipherSuite)), out);
    require_noerr(SSLGetNumberEnabledCiphers(ssl, &num_enabled), out);

    require(num_enabled==2, out); /* 2 ciphers in the above table are supported */

    /* Success! */
    fail=0;

out:
    return fail;
}


- (void)test_dhe: (SSLProtocolSide) side dhe_enabled: (bool) dhe_enabled
{
    SSLContextRef ssl = NULL;
    bool server = (side == kSSLServerSide);

    ssl=SSLCreateContext(kCFAllocatorDefault, side, kSSLStreamType);
    XCTAssert(ssl != NULL, "test_dhe: SSLCreateContext(1) failed (%s, %s)", server?"server":"client", dhe_enabled?"enabled":"disabled");
    require(ssl, out);

    XCTAssertEqual(noErr, SSLSetDHEEnabled(ssl, dhe_enabled),"test_dhe: SSLSetDHEEnabled failed (%s, %s)", server?"server":"client", dhe_enabled?"enabled":"disabled");

    unsigned num = (dhe_enabled?sizeof(legacy_DHE_ciphersuites):sizeof(legacy_ciphersuites))/sizeof(SSLCipherSuite);
    const SSLCipherSuite *ciphers = dhe_enabled?legacy_DHE_ciphersuites:legacy_ciphersuites;
    /* The order of this tests does matter, be careful when adding tests */
    XCTAssert(!test_GetSupportedCiphers(ssl, server), "test_dhe: GetSupportedCiphers test failed (%s, %s)", server?"server":"client", dhe_enabled?"enabled":"disabled");
    XCTAssert(!test_GetEnabledCiphers(ssl, num, ciphers), "test_dhe: GetEnabledCiphers test failed (%s, %s)", server?"server":"client", dhe_enabled?"enabled":"disabled");

    CFRelease(ssl); ssl=NULL;

    ssl=SSLCreateContext(kCFAllocatorDefault, side, kSSLStreamType);
    XCTAssert(ssl, "test_dhe: SSLCreateContext(2) failed (%s, %s)", server?"server":"client", dhe_enabled?"enabled":"disabled");
    require(ssl, out);

    XCTAssert(!test_SetEnabledCiphers(ssl), "test_dhe: SetEnabledCiphers test failed (%s, %s)", server?"server":"client", dhe_enabled?"enabled":"disabled");

out:
    if(ssl) CFRelease(ssl);
}

-(void) test_config: (SSLProtocolSide) side config: (CFStringRef) config num: (unsigned) num cipherList: (const SSLCipherSuite*) ciphers
{
    SSLContextRef ssl = NULL;
    bool server = (side == kSSLServerSide);

    ssl = SSLCreateContext(kCFAllocatorDefault, side, kSSLStreamType);
    XCTAssert(ssl, "test_config: SSLCreateContext(1) failed (%s,%@)", server?"server":"client", config);

    XCTAssertEqual(errSecSuccess, SSLSetSessionConfig(ssl, config), "test_config: SSLSetSessionConfig failed (%s,%@)", server?"server":"client", config);

    /* The order of this tests does matter, be careful when adding tests */
    XCTAssert(!test_GetSupportedCiphers(ssl, server), "test_config: GetSupportedCiphers test failed (%s,%@)", server?"server":"client", config);
    XCTAssert(!test_GetEnabledCiphers(ssl, num, ciphers), "test_config: GetEnabledCiphers test failed (%s,%@)", server?"server":"client", config);

    CFRelease(ssl); ssl=NULL;

    ssl=SSLCreateContext(kCFAllocatorDefault, side, kSSLStreamType);
    XCTAssert(ssl, "test_config: SSLCreateContext(2) failed (%s,%@)", server?"server":"client", config);
    require(ssl, out);

    XCTAssert(!test_SetEnabledCiphers(ssl), "test_config: SetEnabledCiphers test failed (%s,%@)", server?"server":"client", config);

out:
    if(ssl) CFRelease(ssl);
}

-(void) test_default: (SSLProtocolSide) side
{
    SSLContextRef ssl = NULL;
    bool server = (side == kSSLServerSide);

    ssl = SSLCreateContext(kCFAllocatorDefault, side, kSSLStreamType);
    XCTAssert(ssl != NULL, "test_config: SSLCreateContext(1) failed (%s)", server?"server":"client");
    require(ssl, out);

    /* The order of this tests does matter, be careful when adding tests */
    XCTAssert(!test_GetSupportedCiphers(ssl, server), "test_default: GetSupportedCiphers test failed (%s)", server?"server":"client");
    XCTAssert(!test_GetEnabledCiphers(ssl, sizeof(default_ciphersuites)/sizeof(SSLCipherSuite), default_ciphersuites), "test_default: GetEnabledCiphers test failed (%s)", server?"server":"client");

    CFRelease(ssl); ssl=NULL;

    ssl = SSLCreateContext(kCFAllocatorDefault, side, kSSLStreamType);
    XCTAssert(ssl, "test_default: SSLCreateContext(2) failed (%s)", server?"server":"client");
    require(ssl, out);

    XCTAssert(!test_SetEnabledCiphers(ssl), "test_config: SetEnabledCiphers test failed (%s)", server?"server":"client");

out:
    if (ssl) {
        CFRelease(ssl);
    }
}

-(void) test_get_cipher_tls_version
{
    SSLContextRef ctx = NULL;
    size_t num_ciphers;
    SSLCipherSuite *ciphers = NULL;
    SSLProtocol sslmin, sslmax;

    ctx = SSLCreateContext(kCFAllocatorDefault, kSSLClientSide, kSSLStreamType);
    XCTAssert(ctx, "Error creating SSL context");
    XCTAssertEqual(errSecSuccess, SSLGetNumberEnabledCiphers(ctx, &num_ciphers));
    ciphers = (SSLCipherSuite *) malloc(num_ciphers * sizeof (SSLCipherSuite));
    
    XCTAssertEqual(errSecSuccess, SSLGetEnabledCiphers(ctx, ciphers, &num_ciphers), "Error getting enabled ciphers");
    for (size_t i = 0; i < num_ciphers; i++) {
        sslmin = SSLCiphersuiteMinimumTLSVersion(ciphers[i]);
        XCTAssertNotEqual(kSSLProtocolUnknown, sslmin);
        sslmax = SSLCiphersuiteMaximumTLSVersion(ciphers[i]);
        XCTAssertNotEqual(kSSLProtocolUnknown, sslmax);
    }
    free(ciphers);
    CFReleaseNull(ctx);
}

-(void) test_cipher_group_to_list
{
    SSLCiphersuiteGroup group = kSSLCiphersuiteGroupDefault;
    size_t cipher_count = 0;
    const SSLCipherSuite *list = SSLCiphersuiteGroupToCiphersuiteList(group, &cipher_count);
    XCTAssert(list, "Error getting cipher list for group");
}

-(void) testSSLCiphers
{
    [self test_dhe:kSSLClientSide dhe_enabled:true];
    [self test_dhe:kSSLServerSide dhe_enabled:true];
	[self test_dhe:kSSLClientSide dhe_enabled:false];
    [self test_dhe:kSSLServerSide dhe_enabled:false];

    [self test_default:kSSLClientSide];
    [self test_default:kSSLServerSide];

#define TEST_CONFIG(x, y) do {  \
    [self test_config:kSSLClientSide config:x num:sizeof(y)/sizeof(SSLCipherSuite) cipherList:y]; \
    [self test_config:kSSLServerSide config:x num:sizeof(y)/sizeof(SSLCipherSuite) cipherList:y]; \
} while(0)

    TEST_CONFIG(kSSLSessionConfig_ATSv1, ATSv1_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_ATSv1_noPFS, ATSv1_noPFS_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_legacy, legacy_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_legacy_DHE, legacy_DHE_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_standard, standard_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_RC4_fallback, legacy_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_TLSv1_fallback, default_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_TLSv1_RC4_fallback, legacy_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_default, default_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_anonymous, anonymous_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_3DES_fallback, default_ciphersuites);
    TEST_CONFIG(kSSLSessionConfig_TLSv1_3DES_fallback, default_ciphersuites);

}

@end

#pragma clang diagnostic pop
