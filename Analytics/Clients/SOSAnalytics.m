/*
 * Copyright (c) 2017 Apple Inc. All Rights Reserved.
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

#if __OBJC2__

#import "SOSAnalytics.h"
#include <utilities/SecFileLocations.h>
#include <sys/stat.h>

NSString* const CKDKVSPerformanceCountersSampler = @"CKDKVSPerformanceCounterSampler";

CKDKVSPerformanceCounter* const CKDKVSPerfCounterSynchronize = (CKDKVSPerformanceCounter*)@"CKDKVS-synchronize";
CKDKVSPerformanceCounter* const CKDKVSPerfCounterSynchronizeWithCompletionHandler = (CKDKVSPerformanceCounter*)@"CKDKVS-synchronizeWithCompletionHandler";
CKDKVSPerformanceCounter* const CKDKVSPerfCounterIncomingMessages = (CKDKVSPerformanceCounter*)@"CKDKVS-incomingMessages";
CKDKVSPerformanceCounter* const CKDKVSPerfCounterOutgoingMessages = (CKDKVSPerformanceCounter*)@"CKDKVS-outgoingMessages";
CKDKVSPerformanceCounter* const CKDKVSPerfCounterTotalWaitTimeSynchronize = (CKDKVSPerformanceCounter*)@"CKDKVS-totalWaittimeSynchronize";
CKDKVSPerformanceCounter* const CKDKVSPerfCounterLongestWaitTimeSynchronize = (CKDKVSPerformanceCounter*)@"CKDKVS-longestWaittimeSynchronize";
CKDKVSPerformanceCounter* const CKDKVSPerfCounterSynchronizeFailures = (CKDKVSPerformanceCounter*)@"CKDKVS-synchronizeFailures";

@implementation SOSAnalytics

+ (NSString*)databasePath
{
    // This block exists because we moved database locations in 11.3 for easier sandboxing, so we're cleaning up.
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        WithPathInKeychainDirectory(CFSTR("sos_analytics.db"), ^(const char *filename) {
            remove(filename);
        });
        WithPathInKeychainDirectory(CFSTR("sos_analytics.db-wal"), ^(const char *filename) {
            remove(filename);
        });
        WithPathInKeychainDirectory(CFSTR("sos_analytics.db-shm"), ^(const char *filename) {
            remove(filename);
        });
    });
#if TARGET_OS_OSX
    return [SOSAnalytics defaultProtectedAnalyticsDatabasePath:@"sos_analytics"];
#else
    return [SOSAnalytics defaultAnalyticsDatabasePath:@"sos_analytics"];
#endif
}

+ (instancetype)logger
{
    return [super logger];
}

@end

#endif
