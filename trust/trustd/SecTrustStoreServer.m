/*
 * Copyright (c) 2018-2020 Apple Inc. All Rights Reserved.
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

#include <AssertMacros.h>
#import <Foundation/Foundation.h>
#include <stdatomic.h>
#include <notify.h>
#include <sys/stat.h>
#include <Security/Security.h>
#include <Security/SecTrustSettingsPriv.h>
#include <Security/SecPolicyPriv.h>
#include <Security/TrustSettingsSchema.h>
#include <utilities/SecFileLocations.h>
#include <utilities/SecCFWrappers.h>
#import "OTATrustUtilities.h"
#include "trustdFileLocations.h"
#include "trustdVariants.h"
#include "SecTrustStoreServer.h"

#if TARGET_OS_OSX
#include <membership.h>
#endif

/*
 * Each config file is a dictionary with NSString keys corresponding to the appIDs.
 * The value for each appID is the config and is defined (and verified) by the config callbacks.
 */

//
// MARK: Shared Configuration helpers
//
typedef bool(*arrayValueChecker)(id _Nonnull obj);
typedef NSDictionary <NSString*, id>*(^ConfigDiskReader)(NSURL * fileURL, NSError **error);
typedef bool (^ConfigCheckerAndSetter)(id newConfig, id *existingMutableConfig, CFErrorRef *error);
typedef CFTypeRef (^CombineAndCopyAllConfig)(NSDictionary <NSString*,id> *allConfig, CFErrorRef *error);

static bool checkDomainsValuesCompliance(id _Nonnull obj) {
    if (![obj isKindOfClass:[NSString class]]) {
        return false;
    }
    if (SecDNSIsTLD((__bridge CFStringRef)obj)) {
        return false;
    }
    return true;
}

static bool checkCAsValuesCompliance(id _Nonnull obj) {
    if (![obj isKindOfClass:[NSDictionary class]]) {
        return false;
    }
    if (2 != [(NSDictionary*)obj count]) {
        return false;
    }
    if (nil == ((NSDictionary*)obj)[(__bridge NSString*)kSecTrustStoreHashAlgorithmKey] ||
        nil == ((NSDictionary*)obj)[(__bridge NSString*)kSecTrustStoreSPKIHashKey]) {
        return false;
    }
    if (![((NSDictionary*)obj)[(__bridge NSString*)kSecTrustStoreHashAlgorithmKey] isKindOfClass:[NSString class]] ||
        ![((NSDictionary*)obj)[(__bridge NSString*)kSecTrustStoreSPKIHashKey] isKindOfClass:[NSData class]]) {
        return false;
    }
    if (![((NSDictionary*)obj)[(__bridge NSString*)kSecTrustStoreHashAlgorithmKey] isEqualToString:@"sha256"]) {
        return false;
    }
    return true;
}

static bool checkArrayValues(NSString *key, id value, arrayValueChecker checker, CFErrorRef *error) {
    if (![value isKindOfClass:[NSArray class]]) {
        return SecError(errSecParam, error, CFSTR("value for %@ is not an array in configuration"), key);
    }

    __block bool result = true;
    [(NSArray*)value enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        if (!checker(obj)) {
            result = SecError(errSecParam, error, CFSTR("value %lu for %@ is not the expected type"), (unsigned long)idx, key);
            *stop = true;
        }
    }];
    return result;
}

static bool _SecTrustStoreSetConfiguration(CFStringRef appID, CFTypeRef configuration, CFErrorRef *error,
                                           char *configurationType, NSURL *fileURL, _Atomic bool *cachedConfigExists,
                                           char *notification, ConfigDiskReader readConfigFromDisk,
                                           ConfigCheckerAndSetter checkAndSetConfig)
{
    if (!TrustdVariantAllowsFileWrite()) {
        secerror("Unable to write %{public}s in this environment", configurationType);
        return SecError(errSecUnimplemented, error, CFSTR("Unable to write %s in this environment"), configurationType);
    }
    if (!SecOTAPKIIsSystemTrustd()) {
        secerror("Unable to write %{public}s from user agent", configurationType);
        return SecError(errSecWrPerm, error, CFSTR("Unable to write %s from user agent"), configurationType);
    }

    if (!appID) {
        secerror("application-identifier required to set %{public}s", configurationType);
        return SecError(errSecParam, error, CFSTR("application-identifier required to set %s"), configurationType);
    }

    @autoreleasepool {
        NSError *nserror = nil;
        NSMutableDictionary *allConfig = [readConfigFromDisk(fileURL, &nserror) mutableCopy];
        id appConfig = NULL;
        if (allConfig && allConfig[(__bridge NSString*)appID]) {
            appConfig = [allConfig[(__bridge NSString*)appID] mutableCopy];
        } else if (!allConfig) {
            allConfig =  [NSMutableDictionary dictionary];
        }

        if (configuration) {
            id inConfig = (__bridge id)configuration;
            if (!checkAndSetConfig(inConfig, &appConfig, error)) {
                secerror("%{public}s have error: %@", configurationType, error ? *error : nil);
                return false;
            }
        }

        if (!configuration || [appConfig count] == 0) {
            [allConfig removeObjectForKey:(__bridge NSString*)appID];
        } else {
            allConfig[(__bridge NSString*)appID] = appConfig;
        }

        if (![allConfig writeToClassDURL:fileURL permissions:0644 error:&nserror]) {
            secerror("failed to write %{public}s: %@", configurationType, nserror);
            if (error) {
                *error = CFRetainSafe((__bridge CFErrorRef)nserror);
            }
            return false;
        }
        secnotice("config", "wrote %lu configs for %{public}s", (unsigned long)[allConfig count], configurationType);
        atomic_store(cachedConfigExists, [allConfig count] != 0);
        notify_post(notification);
        return true;
    }
}

static void _SecTrustStoreCreateEmptyConfigCache(char *configurationType, _Atomic bool *cachedConfigExists, char *notification, int *notify_token, NSURL *fileURL, ConfigDiskReader readConfigFromDisk)
{
    if (!TrustdVariantAllowsFileWrite()) {
        return;
    }
    @autoreleasepool {
        NSError *read_error = nil;
        NSDictionary <NSString*,id> *allConfig = readConfigFromDisk(fileURL, &read_error);
        if (!allConfig|| [allConfig count] == 0) {
            secnotice("config", "skipping further reads. no %{public}s found: %@", configurationType, read_error);
            atomic_store(cachedConfigExists, false);
        } else {
            secnotice("config", "have %{public}s. will need to read.", configurationType);
            atomic_store(cachedConfigExists, true);
        }

        /* read-only trustds register for notfications from the read-write trustd */
        if (!SecOTAPKIIsSystemTrustd()) {
            uint32_t status = notify_register_check(notification, notify_token);
            if (status == NOTIFY_STATUS_OK) {
                int check = 0;
                status = notify_check(*notify_token, &check);
                (void)check; // notify_check errors if we don't pass a second parameter, but we don't need the value here
            }
            if (status != NOTIFY_STATUS_OK) {
                secerror("failed to establish notification for %{public}s: %u", configurationType, status);
                notify_cancel(*notify_token);
                *notify_token = 0;
            }
        }
    }
}

static CFTypeRef _SecTrustStoreCopyConfiguration(CFStringRef appID, CFErrorRef *error, char *configurationType,
                                                 _Atomic bool *cachedConfigExists, char *notification, int *notify_token,
                                                 NSURL *fileURL, ConfigDiskReader readConfigFromDisk, CombineAndCopyAllConfig combineAllConfig) {
    if (!TrustdVariantAllowsFileWrite()) {
        return NULL;
    }
    @autoreleasepool {
        /* Read the negative cached value as to whether there is config to read */
        if (!SecOTAPKIIsSystemTrustd()) {
            /* Check whether we got a notification. If we didn't, and there is no config set, return NULL.
             * Otherwise, we need to read from disk */
            int check = 0;
            uint32_t check_status = notify_check(*notify_token, &check);
            if (check_status == NOTIFY_STATUS_OK && check == 0 && !atomic_load(cachedConfigExists)) {
                return NULL;
            }
        } else if (!atomic_load(cachedConfigExists)) {
            return NULL;
        }

        /* We need to read the config from disk */
        NSError *read_error = nil;
        NSDictionary <NSString*,id> *allConfig = readConfigFromDisk(fileURL, &read_error);
        if (!allConfig || [allConfig count] == 0) {
            secnotice("config", "skipping further reads. no %{public}s found: %@", configurationType, read_error);
            atomic_store(cachedConfigExists, false);
            return NULL;
        }

        /* If the caller specified an appID, return only the config for that appID */
        if (appID) {
            return CFBridgingRetain(allConfig[(__bridge NSString*)appID]);
        }

        return combineAllConfig(allConfig, error);
    }
}

//
// MARK: CT Exceptions
//

ConfigCheckerAndSetter checkInputExceptionsAndSetAppExceptions = ^bool(id inConfig, id *appConfig, CFErrorRef *error) {
    __block bool result = true;
    if (![inConfig isKindOfClass:[NSDictionary class]]) {
        return SecError(errSecParam, error, CFSTR("value for CT Exceptions is not a dictionary in new configuration"));
    }

    if (!appConfig || (*appConfig && ![*appConfig isKindOfClass:[NSMutableDictionary class]])) {
        return SecError(errSecParam, error, CFSTR("value for CT Exceptions is not a dictionary in current configuration"));
    } else if (!*appConfig) {
        *appConfig = [NSMutableDictionary dictionary];
    }

    NSMutableDictionary *appExceptions = (NSMutableDictionary *)*appConfig;
    NSDictionary *inExceptions = (NSDictionary *)inConfig;
    if (inExceptions.count == 0) {
        return true;
    }
    [inExceptions enumerateKeysAndObjectsUsingBlock:^(NSString *_Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([key isEqualToString:(__bridge NSString*)kSecCTExceptionsDomainsKey]) {
            if (!checkArrayValues(key, obj, checkDomainsValuesCompliance, error)) {
                *stop = YES;
                result = false;
                return;
            }
        } else if ([key isEqualToString:(__bridge NSString*)kSecCTExceptionsCAsKey]) {
            if (!checkArrayValues(key, obj, checkCAsValuesCompliance, error)) {
                *stop = YES;
                result = false;
                return;
            }
        } else {
            result = SecError(errSecParam, error, CFSTR("unknown key (%@) in configuration dictionary"), key);
            *stop = YES;
            result = false;
            return;
        }
        if ([(NSArray*)obj count] == 0) {
            [appExceptions removeObjectForKey:key];
        } else {
            appExceptions[key] = obj;
        }
    }];
    return result;
};

static _Atomic bool gHasCTExceptions = false;
#define kSecCTExceptionsChanged "com.apple.trustd.ct.exceptions-changed"

static NSURL *CTExceptionsOldFileURL(void) {
    return CFBridgingRelease(SecCopyURLForFileInSystemKeychainDirectory(CFSTR("CTExceptions.plist")));
}

static NSURL *CTExceptionsFileURL(void) {
    return CFBridgingRelease(SecCopyURLForFileInPrivateTrustdDirectory(CFSTR("CTExceptions.plist")));
}

ConfigDiskReader readExceptionsFromDisk = ^NSDictionary <NSString*,NSDictionary*> *(NSURL *fileUrl, NSError **error) {
    secdebug("ct", "reading CT exceptions from disk");
    NSDictionary <NSString*,NSDictionary*> *allExceptions = [NSDictionary dictionaryWithContentsOfURL:fileUrl
                                                                                                error:error];
    return allExceptions;
};

bool _SecTrustStoreSetCTExceptions(CFStringRef appID, CFDictionaryRef exceptions, CFErrorRef *error)  {
    return _SecTrustStoreSetConfiguration(appID, exceptions, error, "CT Exceptions", CTExceptionsFileURL(),
                                          &gHasCTExceptions, kSecCTExceptionsChanged, readExceptionsFromDisk,
                                          checkInputExceptionsAndSetAppExceptions);
}

CombineAndCopyAllConfig combineAllCTExceptions = ^CFTypeRef(NSDictionary <NSString*,id> *allExceptions, CFErrorRef *error) {
    NSMutableArray *domainExceptions = [NSMutableArray array];
    NSMutableArray *caExceptions = [NSMutableArray array];
    [allExceptions enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull __unused key, id _Nonnull appConfig,
                                                       BOOL * _Nonnull __unused stop) {
        if (![appConfig isKindOfClass:[NSDictionary class]]) {
            return;
        }

        NSDictionary *appExceptions = (NSDictionary *)appConfig;
        if (appExceptions[(__bridge NSString*)kSecCTExceptionsDomainsKey] &&
            checkArrayValues((__bridge NSString*)kSecCTExceptionsDomainsKey, appExceptions[(__bridge NSString*)kSecCTExceptionsDomainsKey],
                                  checkDomainsValuesCompliance, error)) {
            [domainExceptions addObjectsFromArray:appExceptions[(__bridge NSString*)kSecCTExceptionsDomainsKey]];
        }
        if (appExceptions[(__bridge NSString*)kSecCTExceptionsCAsKey] &&
            checkArrayValues((__bridge NSString*)kSecCTExceptionsCAsKey, appExceptions[(__bridge NSString*)kSecCTExceptionsCAsKey],
                                  checkCAsValuesCompliance, error)) {
            [caExceptions addObjectsFromArray:appExceptions[(__bridge NSString*)kSecCTExceptionsCAsKey]];
        }
    }];
    NSMutableDictionary *exceptions = [NSMutableDictionary dictionaryWithCapacity:2];
    if ([domainExceptions count] > 0) {
        exceptions[(__bridge NSString*)kSecCTExceptionsDomainsKey] = domainExceptions;
    }
    if ([caExceptions count] > 0) {
        exceptions[(__bridge NSString*)kSecCTExceptionsCAsKey] = caExceptions;
    }
    if ([exceptions count] > 0) {
        secdebug("ct", "found %lu CT exceptions on disk", (unsigned long)[exceptions count]);
        atomic_store(&gHasCTExceptions, true);
        return CFBridgingRetain(exceptions);
    }
    return NULL;
};

CFDictionaryRef _SecTrustStoreCopyCTExceptions(CFStringRef appID, CFErrorRef *error) {
    static int notify_token = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _SecTrustStoreCreateEmptyConfigCache("CT Exceptions",
                                             &gHasCTExceptions, kSecCTExceptionsChanged, &notify_token,
                                             CTExceptionsFileURL(), readExceptionsFromDisk);
    });
    return _SecTrustStoreCopyConfiguration(appID, error, "CT Exceptions",
                                           &gHasCTExceptions, kSecCTExceptionsChanged, &notify_token,
                                           CTExceptionsFileURL(), readExceptionsFromDisk, combineAllCTExceptions);
}

//
// MARK: CA Revocation Additions
//

ConfigCheckerAndSetter checkInputAdditionsAndSetAppAdditions = ^bool(id inConfig, id *appConfig, CFErrorRef *error) {
    __block bool result = true;
    if (![inConfig isKindOfClass:[NSDictionary class]]) {
        return SecError(errSecParam, error, CFSTR("value for CA revocation additions is not a dictionary in new configuration"));
    }

    if (!appConfig || (*appConfig && ![*appConfig isKindOfClass:[NSMutableDictionary class]])) {
        return SecError(errSecParam, error, CFSTR("value for CA revocation additions is not a dictionary in existing configuration"));
    } else if (!*appConfig) {
        *appConfig = [NSMutableDictionary dictionary];
    }

    NSMutableDictionary *appAdditions = (NSMutableDictionary *)*appConfig;
    NSDictionary *inAdditions = (NSDictionary *)inConfig;
    if (inAdditions.count == 0) {
        return true;
    }
    [inAdditions enumerateKeysAndObjectsUsingBlock:^(NSString *_Nonnull key, id  _Nonnull obj, BOOL * _Nonnull stop) {
        if ([key isEqualToString:(__bridge NSString*)kSecCARevocationAdditionsKey]) {
            if (!checkArrayValues(key, obj, checkCAsValuesCompliance, error)) {
                *stop = YES;
                result = false;
                return;
            }
        } else {
            result = SecError(errSecParam, error, CFSTR("unknown key (%@) in additions dictionary"), key);
            *stop = YES;
            result = false;
            return;
        }
        if ([(NSArray*)obj count] == 0) {
            [appAdditions removeObjectForKey:key];
        } else {
            appAdditions[key] = obj;
        }
    }];
    return result;
};

static _Atomic bool gHasCARevocationAdditions = false;
#define kSecCARevocationChanged "com.apple.trustd.ca.revocation-changed"

static NSURL *CARevocationOldFileURL(void) {
    return CFBridgingRelease(SecCopyURLForFileInSystemKeychainDirectory(CFSTR("CARevocation.plist")));
}

static NSURL *CARevocationFileURL(void) {
    return CFBridgingRelease(SecCopyURLForFileInPrivateTrustdDirectory(CFSTR("CARevocation.plist")));
}

ConfigDiskReader readRevocationAdditionsFromDisk = ^NSDictionary <NSString*,NSDictionary*> *(NSURL *fileUrl, NSError **error) {
    secdebug("ocsp", "reading CA revocation additions from disk");
    NSDictionary <NSString*,NSDictionary*> *allAdditions = [NSDictionary dictionaryWithContentsOfURL:fileUrl
                                                                                                error:error];
    return allAdditions;
};

bool _SecTrustStoreSetCARevocationAdditions(CFStringRef appID, CFDictionaryRef additions, CFErrorRef *error)  {
    return _SecTrustStoreSetConfiguration(appID, additions, error, "CA Revocation Additions", CARevocationFileURL(),
                                          &gHasCARevocationAdditions, kSecCARevocationChanged, readRevocationAdditionsFromDisk,
                                          checkInputAdditionsAndSetAppAdditions);
}

CombineAndCopyAllConfig combineAllCARevocationAdditions = ^CFTypeRef(NSDictionary <NSString*,id> *allAdditions, CFErrorRef *error) {
    NSMutableArray *caAdditions = [NSMutableArray array];
    [allAdditions enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull __unused key, id _Nonnull appConfig,
                                                       BOOL * _Nonnull __unused stop) {
        if (![appConfig isKindOfClass:[NSDictionary class]]) {
            return;
        }

        NSDictionary *appAdditions = (NSDictionary *)appConfig;
        if (appAdditions[(__bridge NSString*)kSecCARevocationAdditionsKey] &&
            checkArrayValues((__bridge NSString*)kSecCARevocationAdditionsKey,
                                    appAdditions[(__bridge NSString*)kSecCARevocationAdditionsKey],
                                    checkCAsValuesCompliance, error)) {
            [caAdditions addObjectsFromArray:appAdditions[(__bridge NSString*)kSecCARevocationAdditionsKey]];
        }
    }];
    NSMutableDictionary *additions = [NSMutableDictionary dictionaryWithCapacity:1];
    if ([caAdditions count] > 0) {
        additions[(__bridge NSString*)kSecCARevocationAdditionsKey] = caAdditions;
    }
    if ([additions count] > 0) {
        secdebug("ocsp", "found %lu CA revocation additions on disk", (unsigned long)[additions count]);
        atomic_store(&gHasCARevocationAdditions, true);
        return CFBridgingRetain(additions);
    }
    return NULL;
};

CFDictionaryRef _SecTrustStoreCopyCARevocationAdditions(CFStringRef appID, CFErrorRef *error) {
    static int notify_token = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _SecTrustStoreCreateEmptyConfigCache("CA Revocation Additions",
                                             &gHasCARevocationAdditions, kSecCARevocationChanged, &notify_token,
                                             CARevocationFileURL(), readRevocationAdditionsFromDisk);
    });
    return _SecTrustStoreCopyConfiguration(appID, error, "CA Revocation Additions",
                                           &gHasCARevocationAdditions, kSecCARevocationChanged, &notify_token,
                                           CARevocationFileURL(), readRevocationAdditionsFromDisk, combineAllCARevocationAdditions);
}

//
// MARK: Transparent Connection Pins
//
static _Atomic bool gHasTransparentConnectionPins = false;
#define kSecTransparentConnectionPinsChanged "com.apple.trustd.hrn.pins-changed"
const NSString *kSecCAPinsKey = @"CAPins";

static NSURL *TransparentConnectionPinsOldFileURL(void) {
    return CFBridgingRelease(SecCopyURLForFileInSystemKeychainDirectory(CFSTR("TransparentConnectionPins.plist")));
}

static NSURL *TransparentConnectionPinsFileURL(void) {
    return CFBridgingRelease(SecCopyURLForFileInPrivateTrustdDirectory(CFSTR("TransparentConnectionPins.plist")));
}

ConfigDiskReader readPinsFromDisk = ^NSDictionary <NSString*,NSArray*> *(NSURL *fileUrl, NSError **error) {
    secdebug("config", "reading Pins from disk");
    NSDictionary <NSString*,NSArray*> *allPins = [NSDictionary dictionaryWithContentsOfURL:fileUrl
                                                                                     error:error];
    return allPins;
};

ConfigCheckerAndSetter checkInputPinsAndSetPins = ^bool(id inConfig, id *appConfig, CFErrorRef *error) {
    if (!appConfig || (*appConfig && ![*appConfig isKindOfClass:[NSMutableArray class]])) {
        return SecError(errSecParam, error, CFSTR("value for Transparent Connection pins is not an array in existing configuration"));
    } else if (!*appConfig) {
        *appConfig = [NSMutableArray array];
    }

    if(!checkArrayValues(@"TransparentConnectionPins", inConfig, checkCAsValuesCompliance, error)) {
        return false;
    }

    // Replace (null input) or remove config
    if (!inConfig) {
        [*appConfig removeAllObjects];
    } else if ([inConfig count] > 0) {
        *appConfig = [(NSArray*)inConfig mutableCopy];
    }
    return true;
};

CombineAndCopyAllConfig combineAllPins = ^CFTypeRef(NSDictionary <NSString*,id> *allConfig, CFErrorRef *error) {
    NSMutableArray *pins = [NSMutableArray  array];
    [allConfig enumerateKeysAndObjectsUsingBlock:^(NSString * _Nonnull __unused key, id  _Nonnull obj, BOOL * _Nonnull __unused stop) {
        if (checkArrayValues(@"TransparentConnectionPins", obj, checkCAsValuesCompliance, error)) {
            [pins addObjectsFromArray:(NSArray *)obj];
        }
    }];
    if ([pins count] > 0) {
        secdebug("config", "found %lu Transparent Connection pins on disk", (unsigned long)[pins count]);
        atomic_store(&gHasTransparentConnectionPins, true);
        return CFBridgingRetain(pins);
    }
    return NULL;
};

bool _SecTrustStoreSetTransparentConnectionPins(CFStringRef appID, CFArrayRef pins, CFErrorRef *error)  {
    return _SecTrustStoreSetConfiguration(appID, pins, error, "Transparent Connection Pins", TransparentConnectionPinsFileURL(),
                                          &gHasTransparentConnectionPins, kSecTransparentConnectionPinsChanged,
                                          readPinsFromDisk, checkInputPinsAndSetPins);
}

CFArrayRef _SecTrustStoreCopyTransparentConnectionPins(CFStringRef appID, CFErrorRef *error) {
    static int notify_token = 0;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _SecTrustStoreCreateEmptyConfigCache("Transparent Connection Pins",
                                             &gHasTransparentConnectionPins, kSecTransparentConnectionPinsChanged, &notify_token,
                                             TransparentConnectionPinsFileURL(), readPinsFromDisk);
    });
    return _SecTrustStoreCopyConfiguration(appID, error, "Transparent Connection Pins",
                                           &gHasTransparentConnectionPins, kSecTransparentConnectionPinsChanged, &notify_token,
                                           TransparentConnectionPinsFileURL(), readPinsFromDisk, combineAllPins);
}

//
// MARK: One-time migration
//
#if TARGET_OS_OSX
static const NSString *kLegacyTrustSettingsBasePath = @"/Library/Security/Trust Settings";
static const NSString *kAdminTrustSettingsPlist = @"Admin.plist";
static const NSString *kUserTrustSettingsPlist = @"TrustSettings.plist";

static bool _SecTrustStoreCopyOrCreateTrustSettingsPlist(NSString * _Nonnull srcPath, NSString * _Nonnull dstPath, uid_t uid, gid_t gid, mode_t mode, bool forceReset) {
    NSError *error = NULL;
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *srcURL = [NSURL fileURLWithPath:srcPath isDirectory:NO];
    NSURL *dstURL = [NSURL fileURLWithPath:dstPath isDirectory:NO];
    const char *dst = [dstURL fileSystemRepresentation];

    if (!forceReset && [fileManager fileExistsAtPath:srcPath]) {
        // copy existing trust settings file to destination
        if (![fileManager copyItemAtURL:srcURL toURL:dstURL error:&error]) {
            secerror("unable to migrate %s (%s error %ld)",
                     [srcURL fileSystemRepresentation],
                     [[error domain] UTF8String], (long)[error code]);
            return false;
        }
        secnotice("trustsettings", "migrated trust settings to %s", dst);
    } else {
        // create empty trust settings file at destination, as a migration marker
        // (note: empty file is not sufficient; needs version and trust list)
        NSDictionary *dict = [NSDictionary dictionaryWithObjectsAndKeys:
                              @{}, @"trustList", @1, @"trustVersion", nil];
        if (![dict writeToURL:dstURL error:&error]) {
            secerror("unable to create %s (%s error %ld)",
                     [dstURL fileSystemRepresentation],
                     [[error domain] UTF8String], (long)[error code]);
            return false;
        }
        secnotice("trustsettings", "created empty trust settings at %s", dst);
    }
    if (chown(dst, uid, gid)) {
        int localErrno = errno;
        secerror("failed to change permissions of %s: %s", dst, strerror(localErrno));
        return false;
    }
    if (chmod(dst, mode)) {
        int localErrno = errno;
        secerror("failed to change permissions of %s: %s", dst, strerror(localErrno));
        return false;
    }
    return true; // successfully migrated trust settings
}

static bool _SecTrustStoreVerifyTrustSettingsVersion(NSString *tsPath) {
    // check that the file at this path appears to be a readable trust settings plist
    NSDictionary *tsDict = [NSDictionary dictionaryWithContentsOfFile:tsPath];
    NSNumber *value = [tsDict objectForKey:(__bridge NSString *)kTrustRecordVersion];
    int tsVersion = [value intValue];
    if (tsVersion == kSecTrustRecordVersionCurrent) {
        return true;
    }
    // unable to read expected version entry
    const char *name = [tsPath UTF8String];
    if (!name) { name = "<unknown>"; }
    secerror("%s has trustVersion %d, expected %d",
              name, tsVersion, kSecTrustRecordVersionCurrent);
    return false;
}
#endif // TARGET_OS_OSX

static bool _SecTrustStoreMigrateAdminTrustSettingsPlist(void) {
#if TARGET_OS_OSX
    __block NSString *srcPath = nil;
    __block NSString *dstPath = nil;
    __block bool result = true;

    WithPathInPrivateTrustdDirectory((__bridge CFStringRef)kAdminTrustSettingsPlist, ^(const char *utf8String) {
        srcPath = [NSString stringWithFormat:@"%@/%@", kLegacyTrustSettingsBasePath, kAdminTrustSettingsPlist];
        dstPath = [NSString stringWithCString:utf8String encoding:NSUTF8StringEncoding];
        struct stat sb;
        int ret = stat(utf8String, &sb);
        if (ret != 0) {
            secinfo("trustsettings", "failed to stat Admin.plist: %s", strerror(errno));
            result = false;
        }
    });
    if (result) {
        // file exists at dstPath; check that we can read its version entry
        if (_SecTrustStoreVerifyTrustSettingsVersion(dstPath)) {
            return true;
        }
        // unable to read expected version entry, so reset file contents
    }
    return _SecTrustStoreCopyOrCreateTrustSettingsPlist(srcPath, dstPath, TRUSTD_ROLE_ACCOUNT, TRUSTD_ROLE_ACCOUNT, TRUST_SETTINGS_ADMIN_MODE, result);

#else // !TARGET_OS_OSX
    return true;
#endif
}

static bool _SecTrustStoreMigrateUserTrustSettingsPlist(void) {
#if TARGET_OS_OSX
    __block NSString *srcPath = nil;
    __block NSString *dstPath = nil;
    __block bool result = true;
    __block uid_t euid = geteuid();

    WithPathInPrivateUserTrustdDirectory((__bridge CFStringRef)kUserTrustSettingsPlist, ^(const char *utf8String) {
        uuid_t currentUserUuid;
        int ret = mbr_uid_to_uuid(euid, currentUserUuid);
        if (ret != 0) {
            secerror("failed to get UUID for user(%d) - %d", euid, ret);
            // we won't have a srcPath; if dstPath is missing, this creates an empty file.
        } else {
            NSUUID *userUuid = [[NSUUID alloc] initWithUUIDBytes:currentUserUuid];
            srcPath = [NSString stringWithFormat:@"%@/%@.plist", kLegacyTrustSettingsBasePath, [userUuid UUIDString]];
        }
        dstPath = [NSString stringWithCString:utf8String encoding:NSUTF8StringEncoding];
        struct stat sb;
        ret = stat(utf8String, &sb);
        if (ret != 0) {
            secinfo("trustsettings", "failed to stat user TrustSettings.plist: %s", strerror(errno));
            result = false;
        }
    });
    if (result) {
        // file exists at dstPath; check that we can read its version entry
        if (_SecTrustStoreVerifyTrustSettingsVersion(dstPath)) {
            return true;
        }
        // unable to read expected version entry, so reset file contents
    }
    return _SecTrustStoreCopyOrCreateTrustSettingsPlist(srcPath, dstPath, euid, TRUST_SETTINGS_STAFF_GID, TRUST_SETTINGS_USER_MODE, result);

#else // !TARGET_OS_OSX
    return true;
#endif
}

static bool _SecTrustStoreMigrateConfiguration(NSURL *oldFileURL, NSURL *newFileURL, char *configurationType, ConfigDiskReader readConfigFromDisk)
{
    NSError *error;
    if (readConfigFromDisk(newFileURL, &error)) {
        secdebug("config", "already migrated %{public}s", configurationType);
        return true;
    }
    NSDictionary *config = readConfigFromDisk(oldFileURL, &error);
    if (!config) {
        // always write something to the new config so that we can use it as a migration indicator
        secdebug("config", "no existing %{public}s to migrate: %@", configurationType, error);
        config = [NSDictionary dictionary];
    }

    secdebug("config", "migrating %{public}s", configurationType);
    if (![config writeToClassDURL:newFileURL permissions:0644 error:&error]) {
        secerror("failed to write %{public}s: %@", configurationType, error);
        return false;
    }
    // Delete old file
    WithPathInDirectory(CFBridgingRetain(oldFileURL), ^(const char *utf8String) {
        remove(utf8String);
    });
    return true;

}

void _SecTrustStoreMigrateConfigurations(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        if (SecOTAPKIIsSystemTrustd()) {
            _SecTrustStoreMigrateConfiguration(CTExceptionsOldFileURL(), CTExceptionsFileURL(),
                                               "CT Exceptions", readExceptionsFromDisk);
            _SecTrustStoreMigrateConfiguration(CARevocationOldFileURL(), CARevocationFileURL(),
                                               "CA Revocation Additions", readRevocationAdditionsFromDisk);
            _SecTrustStoreMigrateConfiguration(TransparentConnectionPinsOldFileURL(), TransparentConnectionPinsFileURL(),
                                               "Transparent Connection Pins", readPinsFromDisk);
        }
    });
}

void _SecTrustStoreMigrateTrustSettings(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // Migrates our per-user trust settings (as a plist) from kLegacyTrustSettingsBasePath
        // to the protected data vault location.
        if (SecOTAPKIIsSystemTrustd()) {
            _SecTrustStoreMigrateAdminTrustSettingsPlist();
        }
        _SecTrustStoreMigrateUserTrustSettingsPlist();
    });
}


extern dispatch_queue_t tsReadQueue(void);
extern dispatch_queue_t tsWriteQueue(void);

/* Important: _SecTrustStoreMigratePropertyList is designed to be invoked only by
 * SecTrustStoreMigratePropertyListBlock, which dispatches it asynchronously on the
 * write queue to avoid blocking reads.
 *
 * Note that the provided uid comes either from the XPC audit token when we
 * are called via the XPC interface, or directly from the client via getuid
 * if libtrustd is being compiled into a standalone test app. We have already
 * checked the caller's entitlement on the server side of the XPC interface.
 */
static bool _SecTrustStoreMigratePropertyList(uid_t uid,
    CFPropertyListRef _Nullable plist,
    CFDictionaryRef _Nullable certificates,
    CFErrorRef _Nonnull * _Nullable error)
{
    __block bool result = true;

    // server side of XPC call where we process the incoming plist (rdar://106133178)
    //     - (rdar://106133379: look up a special UUID entry in a new table to see if we migrated first)
    //     - for each entry in plist, get key (sha1 hash) and look up corresponding
    //       cert in certificates dictionary
    //     - create a SecCertificateRef from the cert data
    //     - determine trust store based on uid (_trustd is the Admin trust store)
    //     - given the plist entry, cert, and ts, call _SecTrustStoreSetTrustSettings
    //     - set the special UUID entry in a new table to say that we migrated

    return result;
}

typedef void (^SecTrustStoreMigratePropertyListCompletionHandler)(bool result, CFErrorRef error);

static void SecTrustStoreMigratePropertyListCompleted(const void *userData, bool result, CFErrorRef error) {
    SecTrustStoreMigratePropertyListCompletionHandler completed = (__bridge SecTrustStoreMigratePropertyListCompletionHandler)userData;
    secdebug("trustsettings", "SecTrustStoreMigratePropertyListCompleted: calling completion handler");
    completed(result, error);
    Block_release((__bridge const void*)completed);
}

void SecTrustStoreMigratePropertyListBlock(uid_t uid, CFPropertyListRef _Nullable plist, CFDictionaryRef _Nullable certificates, void (^ _Nonnull completed)(bool result, CFErrorRef _Nullable error)) {
    if (!TrustdVariantAllowsFileWrite() || !TrustdVariantAllowsKeychain()) {
        CFErrorRef localError = NULL;
        SecError(errSecUnimplemented, &localError, CFSTR("Trust settings not implemented in this environment"));
        completed(false, localError);
        return;
    }

    SecTrustStoreMigratePropertyListCompletionHandler userData = (__bridge SecTrustStoreMigratePropertyListCompletionHandler) Block_copy((__bridge const void *)completed);
    CFRetainSafe(plist);
    CFRetainSafe(certificates);
    secdebug("trustsettings", "SecTrustStoreMigratePropertyListBlock: queuing async task on trustsettings.write");

    /* Dispatch the actual function call to process the input plist asynchronously,
     * and return immediately to avoid blocking incoming XPC messages. The
     * completion block takes care of sending back a reply to the client. */
    dispatch_async(tsWriteQueue(), ^{
        secdebug("trustsettings", "SecTrustStoreMigratePropertyListBlock: task started, calling _SecTrustStoreMigratePropertyList");
        CFErrorRef localError = NULL;
        bool ok = _SecTrustStoreMigratePropertyList(uid, plist, certificates, &localError);
        SecTrustStoreMigratePropertyListCompleted((__bridge const void *)userData, ok, localError);
        CFReleaseSafe(localError);
        CFReleaseSafe(certificates);
        CFReleaseSafe(plist);
    });
}

// NO_SERVER Shim code only, xpc interface should call SecTrustStoreMigratePropertyListBlock() directly
bool SecTrustStoreMigratePropertyList(uid_t uid,
    CFPropertyListRef _Nullable plist,
    CFDictionaryRef _Nullable certificates,
    CFErrorRef _Nonnull * _Nullable error)
{
    __block dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block bool result = false;
    __block dispatch_queue_t queue = dispatch_queue_create("truststore.write.recursive", DISPATCH_QUEUE_SERIAL);
    secdebug("trustsettings", "SecTrustStoreMigratePropertyList: queuing async task on truststore.write.recursive");

    /* We need to use the async call with the semaphore here instead of a synchronous call
     * because we will return from SecTrustStoreMigratePropertyListBlock immediately before
     * the work is completed. The return is necessary in the XPC interface to avoid blocking,
     * but here, we need to wait for completion before we can return a result. */
    dispatch_async(queue, ^{
        secdebug("trustsettings", "SecTrustStoreMigratePropertyList: calling SecTrustStoreMigratePropertyListBlock");
        SecTrustStoreMigratePropertyListBlock(uid, plist, certificates, ^(bool completionResult, CFErrorRef completionError) {
            secdebug("trustsettings", "SecTrustStoreMigratePropertyListBlock: completion block called");
            result = completionResult;
            if (completionResult == false) {
                if (error) {
                    *error = completionError;
                    CFRetainSafe(completionError);
                }
            }
            dispatch_semaphore_signal(done);
        });
    });
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    done = NULL; // was dispatch_release(done);
    queue = NULL; // was dispatch_release(queue);
    return result;
}

