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
#include "trust/trustd/trustd_spi.h"
#include "trust/trustd/SecRevocationDb.h"
#include <Security/SecCertificatePriv.h>
#include <Security/SecTrustPriv.h>
#include <Security/SecPolicy.h>
#include <Security/SecPolicyPriv.h>
#include <Security/SecTrustSettings.h>
#include <Security/SecTrustSettingsPriv.h>
#include "OSX/utilities/SecCFWrappers.h"
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <os/transaction_private.h>

#if TARGET_OS_IPHONE
#include <Security/SecTrustStore.h>
#else
#define kSystemLoginKeychainPath "/Library/Keychains/System.keychain"
#include <Security/SecKeychain.h>
#endif

#import "../TestMacroConversions.h"
#import "TrustEvaluationTestCase.h"

@implementation TrustEvaluationTestCase

static os_transaction_t transaction = nil;

/* Build in trustd functionality to the tests */
+ (void) setUp {
    transaction = os_transaction_create("com.apple.trusttests.noExitWhenClean");
    /* Use the production Valid DB by default (so we'll have data to test against) */
    CFPreferencesSetAppValue(CFSTR("ValidUpdateServer"), kValidUpdateProdServer, kSecurityPreferencesDomain);
    CFPreferencesSetAppValue(CFSTR("DefaultHTTPTimeout"), (__bridge CFNumberRef)(@10), kSecurityPreferencesDomain);
    CFPreferencesAppSynchronize(kSecurityPreferencesDomain);

    NSURL *tmpDirURL = setUpTmpDir();
    trustd_init((__bridge CFURLRef) tmpDirURL);
}

- (id)addTrustSettingsForCert:(SecCertificateRef)cert trustSettings:(id)trustSettings
{
#if TARGET_OS_IPHONE
    SecTrustStoreRef defaultStore = SecTrustStoreForDomain(kSecTrustStoreDomainUser);
    OSStatus status = SecTrustStoreSetTrustSettings(defaultStore, cert, (__bridge CFTypeRef)trustSettings);
    XCTAssert(errSecSuccess == status, "failed to set trust settings: %d", (int)status);
    return nil;
#else
    /* Since we're putting trust settings in the admin domain,
     * we need to add the certs to the system keychain. */
    SecKeychainRef kcRef = NULL;
    CFArrayRef certRef = NULL;
    NSDictionary *attrs = nil;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    SecKeychainOpen(kSystemLoginKeychainPath, &kcRef);
#pragma clang diagnostic pop
    if (!kcRef) {
        return nil;
    }

    /* Since we're interacting with the keychain we need a framework cert */
    SecCertificateRef frameworkCert = SecFrameworkCertificateCreateFromTestCert(cert);
    attrs = @{(__bridge NSString*)kSecValueRef: (__bridge id)frameworkCert,
              (__bridge NSString*)kSecUseKeychain: (__bridge id)kcRef,
              (__bridge NSString*)kSecReturnPersistentRef: @YES};
    OSStatus status = SecItemAdd((CFDictionaryRef)attrs, (void *)&certRef);
    XCTAssert(errSecSuccess == status, "failed to add cert to keychain: %d", status);
    id result = ((__bridge NSArray*)certRef)[0];
    CFReleaseNull(kcRef);
    CFReleaseNull(certRef);

    status = SecTrustSettingsSetTrustSettings(frameworkCert, kSecTrustSettingsDomainAdmin,
                                              (__bridge CFTypeRef)trustSettings);
    XCTAssert(errSecSuccess == status, "failed to set trust settings: %d", status);
    usleep(20000);

    CFReleaseNull(frameworkCert);
    return result;
#endif
}


- (id)addTrustSettingsForCert:(SecCertificateRef)cert
{
    NSDictionary *trustSettings = @{ (__bridge NSString*)kSecTrustSettingsResult: @(kSecTrustSettingsResultTrustRoot)};
    Boolean isSelfSigned = false;
    XCTAssert(errSecSuccess == SecCertificateIsSelfSigned(cert, &isSelfSigned));
    if (!isSelfSigned) {
        trustSettings = @{ (__bridge NSString*)kSecTrustSettingsResult: @(kSecTrustSettingsResultTrustAsRoot)};
    }

    return [self addTrustSettingsForCert:cert trustSettings:trustSettings];
}

- (void)removeTrustSettingsForCert:(SecCertificateRef)cert persistentRef:(id)persistentRef
{
#if TARGET_OS_IPHONE
    SecTrustStoreRef defaultStore = SecTrustStoreForDomain(kSecTrustStoreDomainUser);
    XCTAssert(errSecSuccess == SecTrustStoreRemoveCertificate(defaultStore, cert), "failed to remove trust settings");
#else
    SecCertificateRef frameworkCert = SecFrameworkCertificateCreateFromTestCert(cert);
    XCTAssert(errSecSuccess == SecTrustSettingsRemoveTrustSettings(frameworkCert, kSecTrustSettingsDomainAdmin),
              "failed to remove trust settings");
    XCTAssert(errSecSuccess == SecItemDelete((CFDictionaryRef)@{ (__bridge NSString*)kSecValuePersistentRef: persistentRef}),
              "failed to remove item from keychain");
    CFReleaseNull(frameworkCert);
#endif
}

const CFStringRef kSecurityPreferencesDomain = CFSTR("com.apple.security");
const CFStringRef kTestSystemRootKey = CFSTR("TestSystemRoot");

- (void)setTestRootAsSystem:(const uint8_t *)sha256hash
{
    NSData *rootHash = [NSData dataWithBytes:sha256hash length:32];
    CFPreferencesSetAppValue(kTestSystemRootKey, (__bridge CFDataRef)rootHash, kSecurityPreferencesDomain);
    CFPreferencesAppSynchronize(kSecurityPreferencesDomain);
}

- (void)removeTestRootAsSystem
{
    CFPreferencesSetAppValue(kTestSystemRootKey, NULL, kSecurityPreferencesDomain);
    CFPreferencesAppSynchronize(kSecurityPreferencesDomain);
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

/* MARK: run test methods from regressionBase */
- (void)runOneLeafTest:(SecPolicyRef)policy
               anchors:(NSArray *)anchors
         intermediates:(NSArray *)intermediates
              leafPath:(NSString *)path
        expectedResult:(bool)expectedResult
          expectations:(NSObject *)expectations
            verifyDate:(NSDate *)date
{
    NSString* fileName = [path lastPathComponent];
    NSString *reason = NULL;
    SecTrustRef trustRef = NULL;
    NSMutableArray* certArray = NULL;
    SecCertificateRef certRef = NULL;
    CFErrorRef error = NULL;

    if (expectations) {
        if ([expectations isKindOfClass: [NSString class]]) {
            reason = (NSString *)expectations;
        } else if ([expectations isKindOfClass: [NSDictionary class]]) {
            NSDictionary *dict = (NSDictionary *)expectations;
            NSObject *value = [dict valueForKey:@"valid"];
            if (value) {
                if ([value isKindOfClass: [NSNumber class]]) {
                    expectedResult = [(NSNumber *)value boolValue];
                } else {
                    NSLog(@"Unexpected valid value %@ in dict for key %@", value, fileName);
                }
            }
            value = [dict valueForKey:@"reason"];
            if (value) {
                if ([value isKindOfClass: [NSString class]]) {
                    reason = (NSString *)value;
                } else {
                    NSLog(@"Unexpected reason value %@ in dict for key %@", value, fileName);
                }
            }
        } else if ([expectations isKindOfClass: [NSNumber class]]) {
            expectedResult = [(NSNumber *)expectations boolValue];
        } else {
            NSLog(@"Unexpected class %@ value %@ for key %@", [expectations class], expectations, fileName);
        }
    }

    certRef = SecCertificateCreateWithData(NULL, (CFDataRef)[NSData dataWithContentsOfFile:path]);
    if (!certRef) {
        if (reason) {
            fail("TODO test: %@ unable to create certificate, %@", fileName, reason);
        } else {
            fail("PARSE %@ unable to create certificate", fileName);
        }
        goto exit;
    }

    certArray = [NSMutableArray arrayWithArray:intermediates];
    [certArray insertObject:(__bridge id)certRef atIndex:0]; //The certificate to be verified must be the first in the array.

    OSStatus err;
    err = SecTrustCreateWithCertificates((__bridge CFTypeRef _Nonnull)(certArray), policy, &trustRef);
    if (err) {
        ok_status(err, "SecTrustCreateWithCertificates");
        goto exit;
    }
    if ([anchors count]) {
        SecTrustSetAnchorCertificates(trustRef, (CFArrayRef)anchors);
        SecTrustSetAnchorCertificatesOnly(trustRef, false);
    }

    SecTrustSetVerifyDate(trustRef, (__bridge CFDateRef)date);

    BOOL isValid = SecTrustEvaluateWithError(trustRef, &error);
    if (reason) {
        XCTAssertFalse(isValid == expectedResult, "TODO test: %@%@", fileName, error);
    } else {
        ok(isValid == expectedResult, "%s %@%@", expectedResult ? "REGRESSION" : "SECURITY", fileName, error);
    }

exit:
    CFReleaseSafe(trustRef);
    CFReleaseSafe(certRef);
    CFReleaseSafe(error);
}

- (void)runCertificateTestFor:(SecPolicyRef)policy
                      anchors:(NSArray *)anchors
                intermediates:(NSArray *)intermediates
                    leafPaths:(NSMutableArray *)leafPaths
                 expectations:(NSDictionary *)expect
                   verifyDate:(NSDate *)date
{
    /* Sort the tests by name. */
    [leafPaths sortUsingSelector:@selector(compare:)];

    for (NSString* path in leafPaths) {
        NSString* fileName = [path lastPathComponent];
        [self runOneLeafTest:policy anchors:anchors intermediates:intermediates leafPath:path expectedResult:![fileName hasPrefix:@"Invalid"] expectations:[expect objectForKey:fileName] verifyDate:date];
    }
}


- (void)runCertificateTestForDirectory:(SecPolicyRef)policy subDirectory:(NSString *)resourceSubDirectory verifyDate:(NSDate*)date
{
    NSMutableArray* allRoots = [NSMutableArray array];
    NSMutableArray* allCAs = [NSMutableArray array];
    NSMutableArray* certTests = [NSMutableArray array];
    NSDictionary* expect = NULL;

    NSURL* filesDirectory = [[[NSBundle bundleForClass:[self class]] resourceURL] URLByAppendingPathComponent:resourceSubDirectory];
    for (NSURL* fileURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:filesDirectory includingPropertiesForKeys:[NSArray array] options:NSDirectoryEnumerationSkipsSubdirectoryDescendants error:nil]) {
        NSString* path = [fileURL path];
        if ([path hasSuffix:@"Cert.crt"]) {
            SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (CFDataRef)[NSData dataWithContentsOfFile:path]);
            [allCAs addObject:(__bridge id)certRef];
            CFReleaseNull(certRef);
        } else if ([path hasSuffix:@"RootCertificate.crt"]) {
            SecCertificateRef certRef = SecCertificateCreateWithData(NULL, (CFDataRef)[NSData dataWithContentsOfFile:path]);
            [allRoots addObject:(__bridge id)certRef];
            CFReleaseNull(certRef);
        } else if ([path hasSuffix:@".crt"]) {
            [certTests addObject:path];
        } else if ([path hasSuffix:@".plist"]) {
            if (expect) {
                fail("Multiple .plist files found in %@", filesDirectory);
            } else {
                expect = [NSDictionary dictionaryWithContentsOfFile:path];
            }
        }
    }

    [self runCertificateTestFor:policy anchors:allRoots intermediates:allCAs leafPaths:certTests expectations:expect verifyDate:date];
}

@end

/* MARK: Framework type conversion functions */

typedef SecCertificateRef (*cert_create_f)(CFAllocatorRef allocator,
                           const UInt8 *der_bytes, CFIndex der_length);
CF_RETURNS_RETAINED _Nullable
SecCertificateRef SecFrameworkCertificateCreate(const uint8_t * _Nonnull der_bytes, CFIndex der_length) {
    static cert_create_f FrameworkCertCreateFunctionPtr = NULL;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        void *framework = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (framework) {
            FrameworkCertCreateFunctionPtr = dlsym(framework, "SecCertificateCreateWithBytes");
        }
    });

    if (FrameworkCertCreateFunctionPtr) {
        return FrameworkCertCreateFunctionPtr(NULL, der_bytes, der_length);
    } else {
        NSLog(@"WARNING: not using Security framework certificate");
        return SecCertificateCreateWithBytes(NULL, der_bytes, der_length);
    }
}

SecCertificateRef SecFrameworkCertificateCreateFromTestCert(SecCertificateRef cert) {
    return SecFrameworkCertificateCreate(SecCertificateGetBytePtr(cert), SecCertificateGetLength(cert));
}

typedef  SecPolicyRef (*ssl_policy_create_f)(Boolean server, CFStringRef hostname);
SecPolicyRef SecFrameworkPolicyCreateSSL(Boolean server, CFStringRef __nullable hostname) {
    static ssl_policy_create_f FrameworkPolicyCreateFunctionPtr = NULL;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        void *framework = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (framework) {
            FrameworkPolicyCreateFunctionPtr  = dlsym(framework, "SecPolicyCreateSSL");
        }
    });

    if (FrameworkPolicyCreateFunctionPtr) {
        return FrameworkPolicyCreateFunctionPtr(server, hostname);
    } else {
        NSLog(@"WARNING: not using Security framework policy");
        return SecPolicyCreateSSL(server, hostname);
    }
}

typedef  SecPolicyRef (*basic_policy_create_f)(void);
SecPolicyRef SecFrameworkPolicyCreateBasicX509(void) {
    static basic_policy_create_f FrameworkPolicyCreateFunctionPtr = NULL;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        void *framework = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (framework) {
            FrameworkPolicyCreateFunctionPtr  = dlsym(framework, "SecPolicyCreateBasicX509");
        }
    });

    if (FrameworkPolicyCreateFunctionPtr) {
        return FrameworkPolicyCreateFunctionPtr();
    } else {
        NSLog(@"WARNING: not using Security framework policy");
        return SecPolicyCreateBasicX509();
    }
}

typedef  SecPolicyRef (*smime_policy_create_f)(CFIndex smimeUsage, CFStringRef email);
SecPolicyRef SecFrameworkPolicyCreateSMIME(CFIndex smimeUsage, CFStringRef email) {
    static smime_policy_create_f FrameworkPolicyCreateFunctionPtr = NULL;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        void *framework = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (framework) {
            FrameworkPolicyCreateFunctionPtr  = dlsym(framework, "SecPolicyCreateSMIME");
        }
    });

    if (FrameworkPolicyCreateFunctionPtr) {
        return FrameworkPolicyCreateFunctionPtr(smimeUsage, email);
    } else {
        NSLog(@"WARNING: not using Security framework policy");
        return SecPolicyCreateSMIME(smimeUsage, email);
    }
}

typedef  SecPolicyRef (*passbook_policy_create_f)(CFStringRef cardIssuer, CFStringRef teamIdentifier);
SecPolicyRef SecFrameworkPolicyCreatePassbookCardSigner(CFStringRef cardIssuer, CFStringRef teamIdentifier) {
    static passbook_policy_create_f FrameworkPolicyCreateFunctionPtr = NULL;
    static dispatch_once_t onceToken;

    dispatch_once(&onceToken, ^{
        void *framework = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
        if (framework) {
            FrameworkPolicyCreateFunctionPtr  = dlsym(framework, "SecPolicyCreatePassbookCardSigner");
        }
    });

    if (FrameworkPolicyCreateFunctionPtr) {
        return FrameworkPolicyCreateFunctionPtr(cardIssuer, teamIdentifier);
    } else {
        NSLog(@"WARNING: not using Security framework policy");
        return SecPolicyCreatePassbookCardSigner(cardIssuer, teamIdentifier);
    }
}
