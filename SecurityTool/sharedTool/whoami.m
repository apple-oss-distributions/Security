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

#include "builtin_commands.h"


int
command_whoami(__unused int argc, __unused char * const * argv)
{
    @autoreleasepool {
        CFErrorRef error = NULL;
        NSDictionary *dict = NULL;

        dict = CFBridgingRelease(_SecSecuritydCopyWhoAmI(&error));
        if (dict) {
            puts([[NSString stringWithFormat:@"the server thinks we are:\n%@\n", dict] UTF8String]);
        } else {
            puts([[NSString stringWithFormat:@"no reply from server: %@", error] UTF8String]);
        }
        if (error)
            CFRelease(error);
    }

    return 0;
}
