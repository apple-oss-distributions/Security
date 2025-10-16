/*
 * Copyright (c) 2018 Apple Inc. All Rights Reserved.
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
 */

#include <AssertMacros.h>
#import <Foundation/Foundation.h>
#include <Security/SecCertificatePriv.h>
#include <utilities/SecCFWrappers.h>

#import "TrustEvaluationTestCase.h"
#include "PathScoringTests_data.h"
#include "../TestMacroConversions.h"

@interface PathScoringTests : TrustEvaluationTestCase
@end

@implementation PathScoringTests

static SecCertificateRef leaf = NULL;
static SecCertificateRef intSHA2 = NULL;
static SecCertificateRef intSHA1 = NULL;
static SecCertificateRef int1024 = NULL;
static SecCertificateRef rootSHA2 = NULL;
static SecCertificateRef rootSHA1 = NULL;
static SecCertificateRef root1024 = NULL;
static SecCertificateRef crossSHA2_SHA1 = NULL;
static SecCertificateRef crossSHA2_SHA2 = NULL;
static SecCertificateRef rootSHA2_2 = NULL;
static SecPolicyRef basicPolicy = NULL;
static SecPolicyRef sslPolicy = NULL;
static NSDate *verifyDate1 = nil;
static NSDate *verifyDate2 = nil;

+ (void)setUp {
    leaf = SecCertificateCreateWithBytes(NULL, _pathScoringLeaf, sizeof(_pathScoringLeaf));
    intSHA2 = SecCertificateCreateWithBytes(NULL, _pathScoringIntSHA2, sizeof(_pathScoringIntSHA2));
    intSHA1 = SecCertificateCreateWithBytes(NULL, _pathScoringIntSHA1, sizeof(_pathScoringIntSHA1));
    int1024 = SecCertificateCreateWithBytes(NULL, _pathScoringInt1024, sizeof(_pathScoringInt1024));
    rootSHA2 = SecCertificateCreateWithBytes(NULL, _pathScoringSHA2Root, sizeof(_pathScoringSHA2Root));
    rootSHA1 = SecCertificateCreateWithBytes(NULL, _pathScoringSHA1Root, sizeof(_pathScoringSHA1Root));
    root1024 = SecCertificateCreateWithBytes(NULL, _pathScoring1024Root, sizeof(_pathScoring1024Root));
    crossSHA2_SHA1 = SecCertificateCreateWithBytes(NULL, _pathScoringSHA2CrossSHA1, sizeof(_pathScoringSHA2CrossSHA1));
    crossSHA2_SHA2 = SecCertificateCreateWithBytes(NULL, _pathScoringSHA2CrossSHA2, sizeof(_pathScoringSHA2CrossSHA2));
    rootSHA2_2 = SecCertificateCreateWithBytes(NULL, _pathScoringSHA2Root2, sizeof(_pathScoringSHA2Root2));

    basicPolicy = SecPolicyCreateBasicX509();
    sslPolicy = SecPolicyCreateSSL(true, NULL);

    // May 1, 2016 at 5:53:20 AM PDT
    verifyDate1 = [NSDate dateWithTimeIntervalSinceReferenceDate:483800000.0];
    // May 27, 2016 at 22:30:00 GMT -- a time between the expiration of _pathScoringIntSHA1 and _pathScoringInt1024
    verifyDate2 = [NSDate dateWithTimeIntervalSinceReferenceDate:486081000.0];
}

+ (void)tearDown {
    CFReleaseNull(leaf);
    CFReleaseNull(intSHA2);
    CFReleaseNull(intSHA1);
    CFReleaseNull(int1024);
    CFReleaseNull(rootSHA2);
    CFReleaseNull(rootSHA1);
    CFReleaseNull(root1024);
    CFReleaseNull(crossSHA2_SHA1);
    CFReleaseNull(crossSHA2_SHA2);
    CFReleaseNull(rootSHA2_2);

    CFReleaseNull(basicPolicy);
    CFReleaseNull(sslPolicy);
}

static bool evaluateTrust(NSArray *certs, NSArray *anchors, SecPolicyRef policy,
                          NSDate *verifyDate, bool expectedResult,
                          NSArray *expectedChain) {
    bool testPassed = false;
    SecTrustRef trust = NULL;
    bool result = false;
    NSArray *chain = nil;
    require_noerr_string(SecTrustCreateWithCertificates((__bridge CFArrayRef)certs,
                                                        policy,
                                                        &trust),
                         errOut, "failed to create trust ref");
    if (anchors) {
        require_noerr_string(SecTrustSetAnchorCertificates(trust, (__bridge CFArrayRef)anchors),
                             errOut, "failed to set anchors");
    }
    require_noerr_string(SecTrustSetVerifyDate(trust, (__bridge CFDateRef)verifyDate),
                         errOut, "failed to set verify date");
    result = SecTrustEvaluateWithError(trust, NULL);

    /* check result */
    if (expectedResult) {
        require_string(result == expectedResult,
                       errOut, "unexpected untrusted chain");
    } else {
        require_string(result == expectedResult,
                       errOut, "unexpected trusted chain");
    }

    /* check the chain that returned */
    chain = CFBridgingRelease(SecTrustCopyCertificateChain(trust));
    require_string([chain count] == [expectedChain count],
                   errOut, "wrong number of certs in result chain");
    NSUInteger ix, count = [expectedChain count];
    for (ix = 0; ix < count; ix++) {
        require_string(CFEqual((__bridge SecCertificateRef)[chain objectAtIndex:ix],
                               (__bridge SecCertificateRef)[expectedChain objectAtIndex:ix]),
                       errOut, "chain didn't match expected");
    }
    testPassed = true;

errOut:
    CFReleaseNull(trust);
    return testPassed;
}

/* Path Scoring Hierarchy
 *                                         leaf
 *                           ^               ^         ^
 *                          /                |          \
 *               intSHA2                    intSHA1     int1024
 *           ^      ^      ^                 ^          ^
 *          /       |       \                |          |
 *  rootSHA2 crossSHA2_SHA1 crossSHA2_SHA2  rootSHA1    root1024
 *                  ^               ^
 *                  |               |
 *              rootSHA1      rootSHA2_2
 */

- (void)exerciseChainsForPolicy:(SecPolicyRef)policy {
    NSArray *certs = nil;
    NSArray *anchors = nil;
    NSArray *chain = nil;
    bool expectedTrustResult = ((policy == basicPolicy) ? true : false);

    /* Choose a short chain over a long chain, when ending in a self-signed cert */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)crossSHA2_SHA2];
    anchors = @[(__bridge id)rootSHA2, (__bridge id)rootSHA2_2];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)rootSHA2];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose shorter chain over longer chain, SHA-2",
       (policy == basicPolicy) ? "accept" : "reject");

    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)intSHA1, (__bridge id)crossSHA2_SHA1];
    anchors = @[(__bridge id)rootSHA1];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA1, (__bridge id)rootSHA1];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose shorter chain over longer chain, SHA-1",
       (policy == basicPolicy) ? "accept" : "reject");

    /* Choose a SHA-2 chain over a SHA-1 chain */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)intSHA1];
    anchors = @[(__bridge id)rootSHA1, (__bridge id)rootSHA2];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)rootSHA2];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose SHA-2 chain over SHA-1 chain, order 1",
       (policy == basicPolicy) ? "accept" : "reject");

    certs = @[(__bridge id)leaf, (__bridge id)intSHA1, (__bridge id)intSHA2];
    anchors = @[(__bridge id)rootSHA2, (__bridge id)rootSHA1];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose SHA-2 chain over SHA-1 chain, order 2",
       (policy == basicPolicy) ? "accept" : "reject");

    /* Choose a longer SHA-2 chain over the shorter SHA-1 chain */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA1, (__bridge id)intSHA2, (__bridge id)crossSHA2_SHA2];
    anchors = @[(__bridge id)rootSHA1, (__bridge id)rootSHA2_2];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)crossSHA2_SHA2, (__bridge id)rootSHA2_2];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose longer SHA-2 chain over shorter SHA-1 chain",
       (policy == basicPolicy) ? "accept" : "reject");

    /* Choose 1024-bit temporally valid chain over 2048-bit invalid chain */
    certs = @[(__bridge id)leaf, (__bridge id)int1024, (__bridge id)intSHA1];
    anchors = @[(__bridge id)root1024, (__bridge id)rootSHA1];
    chain = @[(__bridge id)leaf, (__bridge id)int1024, (__bridge id)root1024];
    ok(evaluateTrust(certs, anchors, policy, verifyDate2, expectedTrustResult, chain),
       "%s test: choose temporally valid chain over invalid chain",
       (policy == basicPolicy) ? "accept" : "reject");

    /* Choose an anchored chain over an unanchored chain */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)intSHA1, (__bridge id)rootSHA2];
    anchors = @[(__bridge id)rootSHA1];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA1, (__bridge id)rootSHA1];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose an anchored chain over an unanchored chain",
       (policy == basicPolicy) ? "accept" : "reject");

    /* Choose an anchored SHA-1 chain over an unanchored SHA-2 chain */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)intSHA1, (__bridge id)rootSHA2];
    anchors = @[(__bridge id)rootSHA1];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA1, (__bridge id)rootSHA1];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose anchored SHA-1 chain over unanchored SHA-2 chain",
       (policy == basicPolicy) ? "accept" : "reject");

    /* Choose an anchored SHA-1 cross-signed chain over unanchored SHA-2 chains */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)rootSHA2,
              (__bridge id)crossSHA2_SHA1, (__bridge id)crossSHA2_SHA2, (__bridge id)rootSHA2_2];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)crossSHA2_SHA1, (__bridge id)rootSHA1];
    ok(evaluateTrust(certs, anchors, policy, verifyDate1, expectedTrustResult, chain),
       "%s test: choose anchored cross-signed chain over unanchored chains",
       (policy == basicPolicy) ? "accept" : "reject");
}

- (void)testPassingEvals {
    [self exerciseChainsForPolicy:basicPolicy];
}

- (void)testFailingEvals {
    [self exerciseChainsForPolicy:sslPolicy];

    /* reject only tests */
    NSArray *certs = nil;
    NSArray *anchors = nil;
    NSArray *chain = nil;

    /* Choose a 2048-bit chain over a 1024-bit chain */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)int1024];
    anchors = @[(__bridge id)rootSHA2, (__bridge id)root1024];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)rootSHA2];
    ok(evaluateTrust(certs, anchors, sslPolicy, verifyDate1, false, chain),
       "reject test: choose 2048-bit chain over 1024-bit chain, order 1");

    certs = @[(__bridge id)leaf, (__bridge id)int1024, (__bridge id)intSHA2];
    anchors = @[(__bridge id)root1024, (__bridge id)rootSHA2];
    ok(evaluateTrust(certs, anchors, sslPolicy, verifyDate1, false, chain),
       "reject test: choose 2048-bit chain over 1024-bit chain, order 2");

    /* Choose a complete chain over an incomplete chain */
    certs = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)intSHA1, (__bridge id)rootSHA1];
    anchors = @[];
    chain = @[(__bridge id)leaf, (__bridge id)intSHA1, (__bridge id)rootSHA1];
    ok(evaluateTrust(certs, anchors, sslPolicy, verifyDate1, false, chain),
       "reject test: choose a chain that ends in a self-signed cert over one that doesn't");

    /* Choose a long chain over a short chain when not ending with a self-signed cert */
    certs = @[(__bridge id)leaf, (__bridge id)crossSHA2_SHA2, (__bridge id)intSHA2];
    anchors = nil;
    chain = @[(__bridge id)leaf, (__bridge id)intSHA2, (__bridge id)crossSHA2_SHA2];
    ok(evaluateTrust(certs, anchors, sslPolicy, verifyDate1, false, chain),
       "reject test: choose longer chain over shorter chain, no roots");
}

@end
