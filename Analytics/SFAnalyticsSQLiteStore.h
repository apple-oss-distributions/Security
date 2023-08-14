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

#import <Security/SFSQLite.h>
#import <Security/SFAnalytics.h>

NS_ASSUME_NONNULL_BEGIN

@interface SFAnalyticsSQLiteStore : SFSQLite

@property (readonly, strong) NSArray* hardFailures;
@property (readonly, strong) NSArray* softFailures;
@property (readonly, strong) NSArray* rockwells;
@property (readonly, strong) NSArray* allEvents;
@property (readonly, strong) NSArray* samples;
@property (readwrite, strong, nullable) NSDate* uploadDate;
@property (readwrite, strong, nullable) NSString* metricsAccountID;

+ (nullable instancetype)storeWithPath:(NSString*)path schema:(NSString*)schema;

- (BOOL)tryToOpenDatabase;
- (void)incrementSuccessCountForEventType:(NSString*)eventType;
- (void)incrementHardFailureCountForEventType:(NSString*)eventType;
- (void)incrementSoftFailureCountForEventType:(NSString*)eventType;
- (NSInteger)successCountForEventType:(NSString*)eventType;
- (NSInteger)hardFailureCountForEventType:(NSString*)eventType;
- (NSInteger)softFailureCountForEventType:(NSString*)eventType;
- (void)addEventDict:(NSDictionary*)eventDict toTable:(NSString*)table;
- (void)addEventDict:(NSDictionary*)eventDict toTable:(NSString*)table timestampBucket:(SFAnalyticsTimestampBucket)timestampBucket;
- (void)addRockwellDict:(NSString *)eventName
               userinfo:(NSDictionary*)eventDict
                toTable:(NSString*)table
        timestampBucket:(SFAnalyticsTimestampBucket)bucket;
- (void)addSample:(NSNumber*)value forName:(NSString*)name;
- (void)removeAllSamplesForName:(NSString*)name;
- (void)clearAllData;

- (NSDictionary*)summaryCounts;

@end

NS_ASSUME_NONNULL_END

#endif
