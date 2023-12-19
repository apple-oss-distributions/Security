/*
 * Copyright (c) 2009-2010,2012-2015 Apple Inc. All Rights Reserved.
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

#import <Foundation/Foundation.h>
#import <Foundation/NSXPCConnection_Private.h>
#import <Security/Security.h>
#import <Security/SecInternalReleasePriv.h>

#import "keychain/SecureObjectSync/CKBridge/SOSCloudKeychainClient.h"

#import <dispatch/dispatch.h>

#import <utilities/debugging.h>
#import <utilities/SecCFWrappers.h>

#import "keychain/SecureObjectSync/SOSInternal.h"
#import <Security/CKKSControlProtocol.h>
#include <Security/SecureObjectSync/SOSCloudCircle.h>

#include "secToolFileIO.h"
#include "accountCirclesViewsPrint.h"
#import "CKKSControlProtocol.h"
#import "SecItemPriv.h"
#import "supdProtocol.h"

#include <stdio.h>

@interface NSString (FileOutput)
- (void) writeToStdOut;
- (void) writeToStdErr;
@end

@implementation NSString (FileOutput)

- (void) writeToStdOut {
    fputs([self UTF8String], stdout);
}
- (void) writeToStdErr {
    fputs([self UTF8String], stderr);
}

@end

@interface NSData (Hexinization)

- (NSString*) asHexString;

@end

@implementation NSData (Hexinization)

- (NSString*) asHexString {
    return (__bridge_transfer NSString*) CFDataCopyHexString((__bridge CFDataRef)self);
}

@end

static NSString *dictionaryToString(NSDictionary *dict) {
    NSMutableString *result = [NSMutableString stringWithCapacity:0];

    NSArray* keys = [[dict allKeys] sortedArrayUsingSelector:@selector(compare:)];
    for(NSString* key in keys) {
        [result appendFormat:@"%@=%@,", key, dict[key]];
    }
    return [result substringToIndex:result.length-(result.length>0)];
}

@implementation NSDictionary (OneLiner)

- (NSString*) asOneLineString {
    return dictionaryToString(self);
}

@end

static void
circle_sysdiagnose(void)
{
    SOSLogSetOutputTo(NULL,NULL);
    SOSCCDumpCircleInformation();
}

static void
engine_sysdiagnose(void)
{
    SOSCCDumpEngineInformation();
}

/*
    Here are the commands to dump out all keychain entries used by HomeKit:
        security item class=genp,sync=1,agrp=com.apple.hap.pairing;
        security item class=genp,sync=0,agrp=com.apple.hap.pairing;
        security item class=genp,sync=0,agrp=com.apple.hap.metadata
*/

static void printSecItems(NSString *subsystem, CFTypeRef result) {
    if (result) {
        if (CFGetTypeID(result) == CFArrayGetTypeID()) {
            NSArray *items = (__bridge NSArray *)(result);

            // Stringify all items, then sort them before printing
            NSMutableArray<NSString*>* itemStrings = [NSMutableArray array];
            NSObject *item;
            for (item in items) {
                if ([item respondsToSelector:@selector(asOneLineString)]) {
                    [itemStrings addObject:[NSString stringWithFormat: @"%@: %@\n", subsystem, [(NSMutableDictionary *)item asOneLineString]]];
                }
            }
            [itemStrings sortUsingSelector:@selector(compare:)];
            for(NSString* str in itemStrings) {
                [str writeToStdOut];
            }
        } else {
            NSObject *item = (__bridge NSObject *)(result);
            if ([item respondsToSelector:@selector(asOneLineString)]) {
                [[NSString stringWithFormat: @"%@: %@\n", subsystem, [(NSMutableDictionary *)item asOneLineString]] writeToStdOut];
            }
        }
    }
}

static void
homekit_sysdiagnose(void)
{
    NSString *kAccessGroupHapPairing  = @"com.apple.hap.pairing";
    NSString *kAccessGroupHapMetadata = @"com.apple.hap.metadata";

    [@"HomeKit keychain state:\n" writeToStdOut];

    // First look for syncable hap.pairing items
    NSMutableDictionary* query = [@{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroupHapPairing,
        (id)kSecAttrSynchronizable: (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecReturnAttributes: @YES,
        (id)kSecReturnData: @NO,
        (id)kSecUseDataProtectionKeychain : @YES,
    } mutableCopy];

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);
    if (status == noErr) {
        printSecItems(@"HomeKit", result);
    }
    CFReleaseNull(result);

    // Now look for non-syncable hap.pairing items
    query[(id)kSecAttrSynchronizable] = @NO;
    status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);
    if (status == noErr) {
        printSecItems(@"HomeKit", result);
    }
    CFReleaseNull(result);

    // Finally look for non-syncable hap.metadata items
    query[(id)kSecAttrAccessGroup] = kAccessGroupHapMetadata;
    status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);
    if (status == noErr) {
        printSecItems(@"HomeKit", result);
    }
    CFReleaseNull(result);
}

static void
unlock_sysdiagnose(void)
{
    NSString *kAccessGroupAutoUnlock  = @"com.apple.continuity.unlock";

    [@"AutoUnlock keychain state:\n" writeToStdOut];

    NSDictionary* query = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroupAutoUnlock,
        (id)kSecAttrAccount : @"com.apple.continuity.auto-unlock.sync",
        (id)kSecAttrSynchronizable: (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecReturnAttributes: @YES,
        (id)kSecReturnData: @NO,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);
    if (status == noErr) {
        printSecItems(@"AutoUnlock", result);
    }
    CFReleaseNull(result);
}

static void
rapport_sysdiagnose(void)
{
    NSString *kAccessGroupRapport  = @"com.apple.rapport";

    [@"Rapport keychain state:\n" writeToStdOut];

    NSDictionary* query = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroupRapport,
        (id)kSecAttrSynchronizable: (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecReturnAttributes: @YES,
        (id)kSecReturnData: @NO,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);
    if (status == noErr) {
        printSecItems(@"rapport", result);
    }
    CFReleaseNull(result);
}

static void
notes_sysdiagnose(void)
{
    NSString *kAccessGroupNotes  = @"group.com.apple.notes";

    [@"Notes keychain state:\n" writeToStdOut];

    NSDictionary* query = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroupNotes,
        (id)kSecAttrSynchronizable: (id)kSecAttrSynchronizableAny,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecReturnAttributes: @YES,
        (id)kSecReturnData: @NO,
    };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &result);
    if (status == noErr) {
        // Unfortunately, Notes saves the account's DSID (or the string "local") under labl.
        // Since we don't want to log the DSID to the sysdiagnose, redact it (on external builds).
        NSMutableArray* cleanedItems = [NSMutableArray array];
        NSMutableDictionary* dsids = [NSMutableDictionary dictionary];
        uint64_t redactions = 1;

        for(NSDictionary* item in (__bridge NSDictionary*)result) {
            NSMutableDictionary* mutableItem = [item mutableCopy];

            NSString* labl = mutableItem[(id)kSecAttrLabel];
            if(!SecIsInternalRelease() && labl != nil && ![labl isEqualToString:@"local"]) {
                // redact!
                NSString* existing = dsids[labl];
                if(!existing) {
                    existing = [NSString stringWithFormat:@"<REDACTED-LABL-%llu>", redactions];
                    redactions += 1;
                    dsids[labl] = existing;
                }
                mutableItem[(id)kSecAttrLabel] = existing;

            } else {
                // don't change mutableItem
            }

            [cleanedItems addObject:mutableItem];
        }

        printSecItems(@"notes", (__bridge CFTypeRef)cleanedItems);
    }
    CFReleaseNull(result);
}

static void
analytics_sysdiagnose(void)
{
    NSXPCConnection* xpcConnection = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.securityuploadd" options:0];
    if (!xpcConnection) {
        [@"failed to setup xpc connection for securityuploadd\n" writeToStdErr];
        return;
    }
    xpcConnection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(supdProtocol)];
    [xpcConnection resume];
    
    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    [[xpcConnection remoteObjectProxyWithErrorHandler:^(NSError* rpcError) {
        [[NSString stringWithFormat:@"Error talking with daemon: %@\n", rpcError] writeToStdErr];
        dispatch_semaphore_signal(semaphore);
    }] getSysdiagnoseDumpWithReply:^(NSString* sysdiagnose) {
        if (sysdiagnose) {
            [[NSString stringWithFormat:@"\nAnalytics sysdiagnose:\n\n%@\n", sysdiagnose] writeToStdOut];
        }
        dispatch_semaphore_signal(semaphore);
    }];
    
    if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 60)) != 0) {
        [@"\n\nError: timed out waiting for response\n" writeToStdErr];
    }
}

static void
kvs_sysdiagnose(void) {
    SOSLogSetOutputTo(NULL,NULL);
    SOSCCDumpCircleKVSInformation(NULL);
}

int
main(int argc, const char ** argv)
{
    @autoreleasepool {
        printf("sysdiagnose keychain\n");

        circle_sysdiagnose();
        engine_sysdiagnose();
        homekit_sysdiagnose();
        unlock_sysdiagnose();
        rapport_sysdiagnose();
        notes_sysdiagnose();
        analytics_sysdiagnose();
        
        // Keep this one last
        kvs_sysdiagnose();
    }
    return 0;
}
