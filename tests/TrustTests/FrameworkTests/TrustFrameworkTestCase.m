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

#import <XCTest/XCTest.h>
#import <Security/SecCertificatePriv.h>
#import "TrustFrameworkTestCase.h"
#include "../../../OSX/sec/ipc/securityd_client.h"


@implementation TrustFrameworkTestCase

+ (void)setUp {
    /* XPC to trustd instead of using trustd built-in */
    gTrustd = NULL;
}

- (id _Nullable) CF_RETURNS_RETAINED SecCertificateCreateFromResource:(NSString *)name
                                                         subdirectory:(NSString *)dir
{
    NSURL *url = [[NSBundle bundleForClass:[self class]] URLForResource:name withExtension:@".cer"
                                                           subdirectory:dir];
    if (!url) {
        url = [[NSBundle bundleForClass:[self class]] URLForResource:name withExtension:@".crt"
                                                        subdirectory:dir];
    }
    NSData *certData = [NSData dataWithContentsOfURL:url];
    if (!certData) {
        return nil;
    }
    SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (__bridge CFDataRef)certData);
    return (__bridge id)cert;
}

- (id _Nullable) CF_RETURNS_RETAINED SecCertificateCreateFromPEMResource:(NSString *)name
                                                            subdirectory:(NSString *)dir
{
    NSURL *url = [[NSBundle bundleForClass:[self class]] URLForResource:name withExtension:@".pem"
                                                           subdirectory:dir];
    NSData *certData = [NSData dataWithContentsOfURL:url];
    if (!certData) {
        return nil;
    }

    SecCertificateRef cert = SecCertificateCreateWithPEM(kCFAllocatorDefault, (__bridge CFDataRef)certData);
    return (__bridge id)cert;
}

@end
