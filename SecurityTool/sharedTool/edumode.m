/*
 * Copyright (c) 2015 Apple Inc. All Rights Reserved.
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
#import <Security/Security.h>
#import <Security/SecItemPriv.h>
#import <err.h>

#include "builtin_commands.h"


int
command_bubble(__unused int argc, __unused char * const * argv)
{
    @autoreleasepool {
        CFErrorRef error = NULL;
        uid_t uid;

        if (argc < 2)
            errx(1, "missing uid argument");

        uid = atoi(argv[1]);
        if (uid == 0)
            errx(1, "syncbubble for root not supported");

        NSArray *services = @[@"com.apple.cloudd.sync", @"com.apple.mailq.sync"];

        if (_SecSyncBubbleTransfer((__bridge CFArrayRef)services, uid, &error)) {
            errx(0, "%s", [[NSString stringWithFormat:@"sync bubble populated"] UTF8String]);
        } else {
            errx(1, "%s", [[NSString stringWithFormat:@"sync bubble failed to inflate: %@", error] UTF8String]);
        }
    }
}

int
command_system_transfer(__unused int argc, __unused char * const * argv)
{
    @autoreleasepool {
        CFErrorRef error = NULL;
        if (_SecSystemKeychainTransfer(&error)) {
            errx(0, "transferred to system keychain");
        } else {
            errx(1, "%s", [[NSString stringWithFormat:@"failed to transfer to system keychain: %@", error] UTF8String]);
        }
    }
}

int
command_system_transcrypt(__unused int argc, __unused char * const * argv)
{
    @autoreleasepool {
        CFErrorRef error = NULL;
        if (_SecSystemKeychainTranscrypt(&error)) {
            errx(0, "transcrypted to system keychain");
        } else {
            errx(1, "%s", [[NSString stringWithFormat:@"failed to transcrypt to system keychain: %@", error] UTF8String]);
        }
    }
}
