/*
 * Copyright (c) 2020 Apple Inc. All Rights Reserved.
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

#ifndef _SECURITY_TRUSTDFILELOCATIONS_H_
#define _SECURITY_TRUSTDFILELOCATIONS_H_

#include <sys/types.h>
#include <CoreFoundation/CFData.h>
#include <CoreFoundation/CFString.h>
#include <CoreFoundation/CFURL.h>
#include "utilities/SecFileLocations.h"

__BEGIN_DECLS

#define TRUSTD_ROLE_ACCOUNT 282

#define TRUST_SETTINGS_STAFF_GID    20
#define TRUST_SETTINGS_USER_MODE    0600    /* owner can read/write, no others have access */
#define TRUST_SETTINGS_ADMIN_MODE   0666    /* writable only if entitled, but as any uid */

// Utility functions to return uuid for the supplied uid
CFStringRef SecCopyUUIDStringForUID(uid_t uid);
CFDataRef SecCopyUUIDDataForUID(uid_t uid);

// Returns a boolean for whether the current instance is the system trustd
bool SecOTAPKIIsSystemTrustd(void);

CFURLRef SecCopyURLForFileInRevocationInfoDirectory(CFStringRef fileName) CF_RETURNS_RETAINED;
CFURLRef SecCopyURLForFileInProtectedTrustdDirectory(CFStringRef fileName) CF_RETURNS_RETAINED;
CFURLRef SecCopyURLForFileInPrivateTrustdDirectory(CFStringRef fileName) CF_RETURNS_RETAINED;
CFURLRef SecCopyURLForFileInPrivateUserTrustdDirectory(CFStringRef fileName) CF_RETURNS_RETAINED;

void WithPathInRevocationInfoDirectory(CFStringRef fileName, void(^operation)(const char *utf8String));
void WithPathInProtectedTrustdDirectory(CFStringRef fileName, void(^operation)(const char *utf8String));
void WithPathInPrivateTrustdDirectory(CFStringRef fileName, void(^operation)(const char *utf8String));
void WithPathInPrivateUserTrustdDirectory(CFStringRef fileName, void(^operation)(const char *utf8String));

void FixTrustdFilePermissions(void);
bool TrustdChangeFileProtectionToClassD(const char *filename, CFErrorRef *error);

#if __OBJC__
#define TrustdFileHelperXPCServiceName "com.apple.trustdFileHelper"
@protocol TrustdFileHelper_protocol
- (void)fixFiles:(void (^)(BOOL, NSError*))reply;
@end

@interface NSDictionary (trustdAdditions)
- (BOOL)writeToClassDURL:(NSURL *)url permissions:(mode_t)permissions error:(NSError **)error;
@end
#endif  // __OBJC__

__END_DECLS

#endif /* _SECURITY_TRUSTDFILELOCATIONS_H_ */
