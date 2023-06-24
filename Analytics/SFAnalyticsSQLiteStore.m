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

#import "SFAnalyticsSQLiteStore.h"
#import "SQLite/SFSQLiteStatement.h"
#import "NSDate+SFAnalytics.h"
#import "Analytics/SFAnalyticsDefines.h"
#import "utilities/debugging.h"

NSString* const SFAnalyticsColumnEventType = @"event_type";
NSString* const SFAnalyticsColumnDate = @"timestamp";
NSString* const SFAnalyticsColumnData = @"data";
NSString* const SFAnalyticsUploadDate = @"upload_date";
NSString* const SFAnalyticsMetricsAccountID = @"account_id";

NS_ASSUME_NONNULL_BEGIN

static NSDictionary * _Nullable deserializedRecordFromRow(id<SFSQLiteRow> row) {
    NSUInteger index = [row indexForColumnName:SFAnalyticsColumnData];
    if (index == NSNotFound) {
        return nil;
    }
    NSError *error;
    NSDictionary *deserializedRecord = [NSPropertyListSerialization propertyListWithData:[row blobAtIndex:index] options:NSPropertyListMutableContainers format:nil error:&error];
    if (!deserializedRecord) {
        secerror("SFAnalytics: failed to deserialize record: %{public}@", error);
    }
    return deserializedRecord;
}

/// A data class that holds a deserialized record and its timestamp, used to
/// sort an array of events by date.
@interface SFAnalyticsEvent : NSObject

+ (instancetype)new NS_UNAVAILABLE;
- (instancetype)init NS_UNAVAILABLE;
- (nullable instancetype)initFromRow:(id<SFSQLiteRow>)row NS_DESIGNATED_INITIALIZER;

@property (readonly, nonatomic) NSDictionary *record;
@property (readonly, nonatomic) NSNumber *timestamp;

@end

@implementation SFAnalyticsEvent

- (nullable instancetype)initFromRow:(id<SFSQLiteRow>)row {
    if ((self = [super init])) {
        _record = deserializedRecordFromRow(row);
        if (!_record) {
            return nil;
        }
        NSUInteger dateIndex = [row indexForColumnName:SFAnalyticsColumnDate];
        _timestamp = @([row doubleAtIndex:dateIndex]);
    }
    return self;
}

@end

NS_ASSUME_NONNULL_END

@implementation SFAnalyticsSQLiteStore

+ (nullable instancetype)storeWithPath:(NSString*)path schema:(NSString*)schema
{
    if (![path length]) {
        seccritical("Cannot init db with empty path");
        return nil;
    }
    if (![schema length]) {
        seccritical("Cannot init db without schema");
        return nil;
    }

    NSString* standardizedPath = path.stringByStandardizingPath;
    SFAnalyticsSQLiteStore* store = [[self alloc] initWithPath:standardizedPath schema:schema];
    NSError* error = nil;
    if (![store openWithError:&error] && !(error && error.code == SQLITE_AUTH)) {
        secerror("SFAnalytics: could not open db at init, will try again later. Error: %@", error);
    }

    return store;
}

- (void)dealloc
{
    [self close];
}

- (BOOL)tryToOpenDatabase
{
    if (!self.isOpen) {
        NSError* error = nil;
        if (![self openWithError:&error]) {
            secerror("SFAnalytics: failed to open analytics db: %@", error);
            return NO;
        }
        secnotice("SFAnalytics", "successfully opened analytics db");
    }
    return YES;
}

- (NSInteger)successCountForEventType:(NSString*)eventType
{
    if (![self tryToOpenDatabase]) {
        return 0;
    }
    return [[[[self select:@[SFAnalyticsColumnSuccessCount] from:SFAnalyticsTableSuccessCount where:@"event_type = ?" bindings:@[eventType]] firstObject] valueForKey:SFAnalyticsColumnSuccessCount] integerValue];
}

- (void)incrementSuccessCountForEventType:(NSString*)eventType
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    NSInteger successCount = [self successCountForEventType:eventType];
    NSInteger hardFailureCount = [self hardFailureCountForEventType:eventType];
    NSInteger softFailureCount = [self softFailureCountForEventType:eventType];
    [self insertOrReplaceInto:SFAnalyticsTableSuccessCount values:@{SFAnalyticsColumnEventType : eventType, SFAnalyticsColumnSuccessCount : @(successCount + 1), SFAnalyticsColumnHardFailureCount : @(hardFailureCount), SFAnalyticsColumnSoftFailureCount : @(softFailureCount)}];
}

- (NSInteger)hardFailureCountForEventType:(NSString*)eventType
{
    if (![self tryToOpenDatabase]) {
        return 0;
    }
    return [[[[self select:@[SFAnalyticsColumnHardFailureCount] from:SFAnalyticsTableSuccessCount where:@"event_type = ?" bindings:@[eventType]] firstObject] valueForKey:SFAnalyticsColumnHardFailureCount] integerValue];
}

- (NSInteger)softFailureCountForEventType:(NSString*)eventType
{
    if (![self tryToOpenDatabase]) {
        return 0;
    }
    return [[[[self select:@[SFAnalyticsColumnSoftFailureCount] from:SFAnalyticsTableSuccessCount where:@"event_type = ?" bindings:@[eventType]] firstObject] valueForKey:SFAnalyticsColumnSoftFailureCount] integerValue];
}

- (void)incrementHardFailureCountForEventType:(NSString*)eventType
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    NSInteger successCount = [self successCountForEventType:eventType];
    NSInteger hardFailureCount = [self hardFailureCountForEventType:eventType];
    NSInteger softFailureCount = [self softFailureCountForEventType:eventType];
    [self insertOrReplaceInto:SFAnalyticsTableSuccessCount values:@{SFAnalyticsColumnEventType : eventType, SFAnalyticsColumnSuccessCount : @(successCount), SFAnalyticsColumnHardFailureCount : @(hardFailureCount + 1), SFAnalyticsColumnSoftFailureCount : @(softFailureCount)}];
}

- (void)incrementSoftFailureCountForEventType:(NSString*)eventType
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    NSInteger successCount = [self successCountForEventType:eventType];
    NSInteger hardFailureCount = [self hardFailureCountForEventType:eventType];
    NSInteger softFailureCount = [self softFailureCountForEventType:eventType];
    [self insertOrReplaceInto:SFAnalyticsTableSuccessCount values:@{SFAnalyticsColumnEventType : eventType, SFAnalyticsColumnSuccessCount : @(successCount), SFAnalyticsColumnHardFailureCount : @(hardFailureCount), SFAnalyticsColumnSoftFailureCount : @(softFailureCount + 1)}];
}

- (NSDictionary*)summaryCounts
{
    if (![self tryToOpenDatabase]) {
        return [NSDictionary new];
    }
    NSMutableDictionary* successCountsDict = [NSMutableDictionary dictionary];
    NSArray* rows = [self selectAllFrom:SFAnalyticsTableSuccessCount where:nil bindings:nil];
    for (NSDictionary* rowDict in rows) {
        NSString* eventName = rowDict[SFAnalyticsColumnEventType];
        if (!eventName) {
            secinfo("SFAnalytics", "ignoring entry in success counts table without an event name");
            continue;
        }

        successCountsDict[eventName] = @{SFAnalyticsTableSuccessCount : rowDict[SFAnalyticsColumnSuccessCount], SFAnalyticsColumnHardFailureCount : rowDict[SFAnalyticsColumnHardFailureCount], SFAnalyticsColumnSoftFailureCount : rowDict[SFAnalyticsColumnSoftFailureCount]};
    }

    return successCountsDict;
}

- (NSArray*)hardFailures
{
    if (![self tryToOpenDatabase]) {
        return [NSArray new];
    }
    return [self select:@[SFAnalyticsColumnData] from:SFAnalyticsTableHardFailures mapEachRow:^id(id<SFSQLiteRow> row) {
        return deserializedRecordFromRow(row);
    }];
}

- (NSArray*)softFailures
{
    if (![self tryToOpenDatabase]) {
        return [NSArray new];
    }
    return [self select:@[SFAnalyticsColumnData] from:SFAnalyticsTableSoftFailures mapEachRow:^id(id<SFSQLiteRow> row) {
        return deserializedRecordFromRow(row);
    }];
}

- (NSArray*)allEvents
{
    if (![self tryToOpenDatabase]) {
        return [NSArray new];
    }

    __auto_type rowToEvent = ^(id<SFSQLiteRow> row) {
        return [[SFAnalyticsEvent alloc] initFromRow:row];
    };

    [self begin];

    NSMutableArray<SFAnalyticsEvent *> *all = [NSMutableArray new];

    NSArray<SFAnalyticsEvent *> *hard = [self select:@[SFAnalyticsColumnDate, SFAnalyticsColumnData] from:SFAnalyticsTableHardFailures mapEachRow:rowToEvent];
    [all addObjectsFromArray:hard];
    hard = nil;

    NSArray<SFAnalyticsEvent *> *soft = [self select:@[SFAnalyticsColumnDate, SFAnalyticsColumnData] from:SFAnalyticsTableSoftFailures mapEachRow:rowToEvent];
    [all addObjectsFromArray:soft];
    soft = nil;

    NSArray<SFAnalyticsEvent *> *notes = [self select:@[SFAnalyticsColumnDate, SFAnalyticsColumnData] from:SFAnalyticsTableNotes mapEachRow:rowToEvent];
    [all addObjectsFromArray:notes];
    notes = nil;

    [self end];

    [all sortUsingDescriptors:@[[NSSortDescriptor sortDescriptorWithKey:@"timestamp" ascending:YES]]];

    return [all valueForKey:@"record"];
}

- (NSArray*)samples
{
    if (![self tryToOpenDatabase]) {
        return [NSArray new];
    }
    return [self select:@[SFAnalyticsColumnSampleName, SFAnalyticsColumnSampleValue] from:SFAnalyticsTableSamples];
}

- (void)addEventDict:(NSDictionary*)eventDict toTable:(NSString*)table timestampBucket:(SFAnalyticsTimestampBucket)bucket
{
    if (![self tryToOpenDatabase]) {
        return;
    }

    NSTimeInterval timestamp = [[NSDate date] timeIntervalSince1970WithBucket:bucket];
    NSError* error = nil;
    NSData* serializedRecord = [NSPropertyListSerialization dataWithPropertyList:eventDict format:NSPropertyListBinaryFormat_v1_0 options:0 error:&error];
    if(!error && serializedRecord) {
        [self insertOrReplaceInto:table values:@{SFAnalyticsColumnDate : @(timestamp), SFAnalyticsColumnData : serializedRecord}];
    }
    if(error && !serializedRecord) {
        secerror("Couldn't serialize failure record: %@", error);
    }
}

- (void)addEventDict:(NSDictionary*)eventDict toTable:(NSString*)table
{
    [self addEventDict:eventDict toTable:table timestampBucket:SFAnalyticsTimestampBucketSecond];
}

- (void)addSample:(NSNumber*)value forName:(NSString*)name
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    [self insertOrReplaceInto:SFAnalyticsTableSamples values:@{SFAnalyticsColumnDate : @([[NSDate date] timeIntervalSince1970]), SFAnalyticsColumnSampleName : name, SFAnalyticsColumnSampleValue : value}];
}

- (void)removeAllSamplesForName:(NSString*)name
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    [self deleteFrom:SFAnalyticsTableSamples where:[NSString stringWithFormat:@"name == '%@'", name] bindings:nil];
}

- (NSDate*)uploadDate
{
    if (![self tryToOpenDatabase]) {
        return nil;     // In other cases return default object but nil is better here to avoid entering the upload flow
    }
    return [self datePropertyForKey:SFAnalyticsUploadDate];
}

- (void)setUploadDate:(NSDate*)uploadDate
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    [self setDateProperty:uploadDate forKey:SFAnalyticsUploadDate];
}

- (NSString*)metricsAccountID
{
    if (![self tryToOpenDatabase]) {
        return nil;
    }
    return [self propertyForKey:SFAnalyticsMetricsAccountID];
}

- (void)setMetricsAccountID:(NSString *)accountID {
    if (![self tryToOpenDatabase]) {
        return;
    }
    if (accountID == nil) {
        [self removePropertyForKey:SFAnalyticsMetricsAccountID];
    } else {
        [self setProperty:accountID forKey:SFAnalyticsMetricsAccountID];
    }
}


- (void)clearAllData
{
    if (![self tryToOpenDatabase]) {
        return;
    }
    [self deleteFrom:SFAnalyticsTableSuccessCount where:@"event_type like ?" bindings:@[@"%"]];
    [self deleteFrom:SFAnalyticsTableHardFailures where:@"id >= 0" bindings:nil];
    [self deleteFrom:SFAnalyticsTableSoftFailures where:@"id >= 0" bindings:nil];
    [self deleteFrom:SFAnalyticsTableSamples where:@"id >= 0" bindings:nil];
}

@end

#endif // OBJC2
