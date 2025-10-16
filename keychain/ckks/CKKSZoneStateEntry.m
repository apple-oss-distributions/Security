/*
 * Copyright (c) 2016 Apple Inc. All Rights Reserved.
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
#import <Foundation/NSKeyedArchiver_Private.h>

#import "CKKSKeychainView.h"

#include <utilities/SecDb.h>
#include "keychain/securityd/SecDbItem.h"
#include "keychain/securityd/SecItemSchema.h"

#if OCTAGON

#import <CloudKit/CloudKit.h>
#import "CKKSZoneStateEntry.h"
#import "keychain/ckks/CKKSRateLimiter.h"
#import "keychain/ckks/CKKSFixups.h"


@implementation CKKSZoneStateEntry

- (instancetype)initWithContextID:(NSString*)contextID
                         zoneName:(NSString*)ckzone
                      zoneCreated:(bool)ckzonecreated
                   zoneSubscribed:(bool)ckzonesubscribed
                      changeToken:(NSData* _Nullable)changetoken
            moreRecordsInCloudKit:(BOOL)moreRecords
                        lastFetch:(NSDate* _Nullable)lastFetch
                         lastScan:(NSDate* _Nullable)lastScan
                        lastFixup:(CKKSFixup)lastFixup
               encodedRateLimiter:(NSData* _Nullable)encodedRateLimiter
          fetchNewestChangesFirst:(BOOL)fetchNewestChangesFirst
              initialSyncFinished:(BOOL)initialSyncFinished
{
    if(self = [super init]) {
        _contextID = contextID;
        _ckzone = ckzone;
        _ckzonecreated = ckzonecreated;
        _ckzonesubscribed = ckzonesubscribed;
        _encodedChangeToken = changetoken;
        _moreRecordsInCloudKit = moreRecords;
        _lastFetchTime = lastFetch;
        _lastLocalKeychainScanTime = lastScan;
        _lastFixup = lastFixup;
        _fetchNewestChangesFirst = fetchNewestChangesFirst;
        _initialSyncFinished = initialSyncFinished;

        self.encodedRateLimiter = encodedRateLimiter;
    }
    return self;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<CKKSZoneStateEntry[%@](%@): created:%@ subscribed:%@ moreRecords:%@ fetchNewestChangesFirst:%@ initialSyncFinished:%@>",
            self.contextID,
            self.ckzone,
            self.ckzonecreated ? @"YES" : @"NO",
            self.ckzonesubscribed ? @"YES" : @"NO",
            self.moreRecordsInCloudKit ? @"YES" : @"NO",
            self.fetchNewestChangesFirst ? @"YES" : @"NO",
            self.initialSyncFinished ? @"YES" : @"NO"
    ];
}

- (BOOL)isEqual: (id) object {
    if(![object isKindOfClass:[CKKSZoneStateEntry class]]) {
        return NO;
    }

    CKKSZoneStateEntry* obj = (CKKSZoneStateEntry*) object;

    return ([self.ckzone isEqualToString: obj.ckzone] &&
            ((self.contextID == nil && obj.contextID == nil) || [self.contextID isEqualToString:obj.contextID]) &&
            self.ckzonecreated == obj.ckzonecreated &&
            self.ckzonesubscribed == obj.ckzonesubscribed &&
            ((self.encodedChangeToken == nil && obj.encodedChangeToken == nil) || [self.encodedChangeToken isEqual: obj.encodedChangeToken]) &&
            self.moreRecordsInCloudKit == obj.moreRecordsInCloudKit &&
            ((self.lastFetchTime == nil && obj.lastFetchTime == nil) || [self.lastFetchTime isEqualToDate: obj.lastFetchTime]) &&
            ((self.rateLimiter == nil && obj.rateLimiter == nil) || [self.rateLimiter isEqual: obj.rateLimiter]) &&
            self.lastFixup == obj.lastFixup &&
            ((self.lastLocalKeychainScanTime == nil && obj.lastLocalKeychainScanTime == nil) || [self.lastLocalKeychainScanTime isEqualToDate: obj.lastLocalKeychainScanTime]) &&
            self.fetchNewestChangesFirst == obj.fetchNewestChangesFirst &&
            self.initialSyncFinished == obj.initialSyncFinished &&
            true) ? YES : NO;
}

+ (instancetype)contextID:(NSString*)contextID
                 zoneName:(NSString*)ckzone
{
    NSError* error = nil;
    CKKSZoneStateEntry* ret = [CKKSZoneStateEntry tryFromDatabase:contextID zoneName:ckzone error:&error];

    if(error) {
        ckkserror_global("ckks", "error fetching CKState(%@): %@", ckzone, error);
    }

    if(!ret) {
        ret = [[CKKSZoneStateEntry alloc] initWithContextID:contextID
                                                   zoneName:ckzone
                                                zoneCreated:false
                                             zoneSubscribed:false
                                                changeToken:nil
                                      moreRecordsInCloudKit:NO
                                                  lastFetch:nil
                                                   lastScan:nil
                                                  lastFixup:CKKSCurrentFixupNumber
                                         encodedRateLimiter:nil
                                    fetchNewestChangesFirst:YES
                                        initialSyncFinished:NO];
    }
    return ret;
}

- (CKServerChangeToken* _Nullable) getChangeToken {
    if(self.encodedChangeToken) {
        NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:self.encodedChangeToken error:nil];
        return [unarchiver decodeObjectOfClass:[CKServerChangeToken class] forKey:NSKeyedArchiveRootObjectKey];
    } else {
        return nil;
    }
}

- (void) setChangeToken: (CKServerChangeToken*) token {
    self.encodedChangeToken = token ? [NSKeyedArchiver archivedDataWithRootObject:token requiringSecureCoding:YES error:nil] : nil;
}

- (NSData*)encodedRateLimiter {
    if(self.rateLimiter == nil) {
        return nil;
    }
    return [NSKeyedArchiver archivedDataWithRootObject:self.rateLimiter requiringSecureCoding:YES error:nil];
}

- (void)setEncodedRateLimiter:(NSData *)encodedRateLimiter {
    if(encodedRateLimiter == nil) {
        self.rateLimiter = nil;
        return;
    }

    NSKeyedUnarchiver* unarchiver = [[NSKeyedUnarchiver alloc] initForReadingFromData:encodedRateLimiter error:nil];
    self.rateLimiter = [unarchiver decodeObjectOfClass: [CKKSRateLimiter class] forKey:NSKeyedArchiveRootObjectKey];
}

#pragma mark - Database Operations

+ (instancetype)fromDatabase:(NSString*)contextID
                    zoneName:(NSString*)ckzone
                       error:(NSError * __autoreleasing *)error
{
    return [self fromDatabaseWhere:@{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone": CKKSNilToNSNull(ckzone),
    } error:error];
}

+ (instancetype)tryFromDatabase:(NSString*)contextID
                       zoneName:(NSString*)ckzone
                          error:(NSError * __autoreleasing *)error
{
    return [self tryFromDatabaseWhere:@{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone": CKKSNilToNSNull(ckzone),
    } error:error];
}

#pragma mark - CKKSSQLDatabaseObject methods

+ (NSString*) sqlTable {
    return @"ckstate";
}

+ (NSArray<NSString*>*) sqlColumns {
    // Note that 'extra' is not currently used, but the schema supports adding a protobuf or other serialized data
    return @[@"contextID", @"ckzone", @"ckzonecreated", @"ckzonesubscribed", @"changetoken", @"lastfetch", @"ratelimiter", @"lastFixup", @"morecoming", @"lastscan", @"extra", @"fetchNewestChangesFirst", @"initialSyncFinished"];
}

- (NSDictionary<NSString*,NSString*>*) whereClauseToFindSelf {
    return @{
        @"contextID": CKKSNilToNSNull(self.contextID),
        @"ckzone": self.ckzone,
    };
}

- (NSDictionary<NSString*,id>*) sqlValues {
    NSISO8601DateFormatter* dateFormat = [[NSISO8601DateFormatter alloc] init];

    return @{
        @"contextID": CKKSNilToNSNull(self.contextID),
        @"ckzone": self.ckzone,
        @"ckzonecreated": [NSNumber numberWithBool:self.ckzonecreated],
        @"ckzonesubscribed": [NSNumber numberWithBool:self.ckzonesubscribed],
        @"changetoken": CKKSNilToNSNull([self.encodedChangeToken base64EncodedStringWithOptions:0]),
        @"lastfetch": CKKSNilToNSNull(self.lastFetchTime ? [dateFormat stringFromDate: self.lastFetchTime] : nil),
        @"ratelimiter": CKKSNilToNSNull([self.encodedRateLimiter base64EncodedStringWithOptions:0]),
        @"lastFixup": [NSNumber numberWithLong:self.lastFixup],
        @"morecoming": [NSNumber numberWithBool:self.moreRecordsInCloudKit],
        @"lastscan": CKKSNilToNSNull(self.lastLocalKeychainScanTime ? [dateFormat stringFromDate:self.lastLocalKeychainScanTime] : nil),
        @"fetchNewestChangesFirst": [NSNumber numberWithBool:self.fetchNewestChangesFirst],
        @"initialSyncFinished": [NSNumber numberWithBool:self.initialSyncFinished],
    };
}

+ (instancetype)fromDatabaseRow:(NSDictionary<NSString*, CKKSSQLResult*>*)row {
    return [[CKKSZoneStateEntry alloc] initWithContextID:row[@"contextID"].asString
                                                zoneName:row[@"ckzone"].asString
                                             zoneCreated:row[@"ckzonecreated"].asBOOL
                                          zoneSubscribed:row[@"ckzonesubscribed"].asBOOL
                                             changeToken:row[@"changetoken"].asBase64DecodedData
                                   moreRecordsInCloudKit:row[@"morecoming"].asBOOL
                                               lastFetch:row[@"lastfetch"].asISO8601Date
                                                lastScan:row[@"lastscan"].asISO8601Date
                                               lastFixup:(CKKSFixup)row[@"lastFixup"].asNSInteger
                                      encodedRateLimiter:row[@"ratelimiter"].asBase64DecodedData
                                 fetchNewestChangesFirst:row[@"fetchNewestChangesFirst"].asBOOL
                                     initialSyncFinished:row[@"initialSyncFinished"].asBOOL
    ];
}

@end

#endif
