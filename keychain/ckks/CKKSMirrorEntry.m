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

#if OCTAGON

#include <AssertMacros.h>

#import <Foundation/Foundation.h>

#import "CKKSKeychainView.h"

#include <utilities/SecDb.h>
#include "keychain/securityd/SecDbItem.h"
#include "keychain/securityd/SecItemSchema.h"


#import <CloudKit/CloudKit.h>
#import "CKKSOutgoingQueueEntry.h"
#import "CKKSMirrorEntry.h"
#import "CKKSSIV.h"

@implementation CKKSMirrorEntry

-(instancetype)initWithCKKSItem:(CKKSItem*)item {
    if((self = [super init])) {
        _item = item;
        _wasCurrent = 0;
    }
    return self;
}

-(instancetype)initWithCKRecord:(CKRecord*)record
                      contextID:(NSString*)contextID
{
    if((self = [super init])) {
        _item = [[CKKSItem alloc] initWithCKRecord:record contextID:contextID];

        _wasCurrent = [record[SecCKRecordServerWasCurrent] unsignedLongLongValue];
    }
    return self;
}

- (NSString*)description {
    return [NSString stringWithFormat: @"<%@[%@](%@): %@>",
            NSStringFromClass([self class]),
            self.item.contextID,
            self.item.zoneID.zoneName,
            self.item.uuid];
}

-(void)setFromCKRecord: (CKRecord*) record {
    [self.item setFromCKRecord: record];
    _wasCurrent = [record[SecCKRecordServerWasCurrent] unsignedLongLongValue];
}

- (bool)matchesCKRecord: (CKRecord*) record {
    return [self matchesCKRecord:record checkServerFields:true];
}

- (bool)matchesCKRecord:(CKRecord*)record checkServerFields:(bool)checkServerFields {
    bool matches = [self.item matchesCKRecord: record];

    if(matches && checkServerFields) {

        // Why is obj-c nullable equality so difficult?
        if(!((record[SecCKRecordServerWasCurrent] == nil && self.wasCurrent == 0) ||
             [record[SecCKRecordServerWasCurrent] isEqual: [NSNumber numberWithUnsignedLongLong:self.wasCurrent]])) {
            ckksinfo_global("ckksitem", "was_current does not match");
            matches = false;
        }
    }
    return matches;
}

#pragma mark - Database Operations

+ (instancetype _Nullable)fromDatabase:(NSString*)uuid
                             contextID:(NSString*)contextID
                                zoneID:(CKRecordZoneID*)zoneID
                                 error:(NSError * __autoreleasing *)error
{
    return [self fromDatabaseWhere: @{
        @"contextID": CKKSNilToNSNull(contextID),
        @"UUID": CKKSNilToNSNull(uuid),
        @"ckzone":CKKSNilToNSNull(zoneID.zoneName)
    } error: error];
}

+ (instancetype _Nullable)tryFromDatabase:(NSString*)uuid
                                contextID:(NSString*)contextID
                                   zoneID:(CKRecordZoneID*)zoneID
                                    error:(NSError * __autoreleasing *)error
{
    return [self tryFromDatabaseWhere: @{
        @"contextID": CKKSNilToNSNull(contextID),
        @"UUID": CKKSNilToNSNull(uuid),
        @"ckzone":CKKSNilToNSNull(zoneID.zoneName)
    } error: error];
}

+ (NSArray<CKKSMirrorEntry*>*)allWithUUID:(NSString*)uuid
                                contextID:(NSString*)contextID
                                    error:(NSError**)error
{
    return [self allWhere:@{
        @"contextID": CKKSNilToNSNull(contextID),
        @"UUID": CKKSNilToNSNull(uuid)
    } error:error];
}

#pragma mark - Property access to underlying CKKSItem

-(NSString*)uuid {
    return self.item.uuid;
}

-(void)setUuid:(NSString *)uuid {
    self.item.uuid = uuid;
}

#pragma mark - CKKSSQLDatabaseObject methods

+ (NSString*) sqlTable {
    return @"ckmirror";
}

+ (NSArray<NSString*>*)sqlColumns {
    return [[CKKSItem sqlColumns] arrayByAddingObjectsFromArray: @[@"wascurrent"]];
}

- (NSDictionary<NSString*,NSString*>*) whereClauseToFindSelf {
    return [self.item whereClauseToFindSelf];
}

- (NSDictionary<NSString*,NSString*>*)sqlValues {
    NSMutableDictionary* values = [[self.item sqlValues] mutableCopy];
    values[@"wascurrent"] = [[NSNumber numberWithUnsignedLongLong:self.wasCurrent] stringValue];
    return values;
}

+ (instancetype)fromDatabaseRow:(NSDictionary<NSString*, CKKSSQLResult*>*)row {
    CKKSMirrorEntry* ckme = [[CKKSMirrorEntry alloc] initWithCKKSItem: [CKKSItem fromDatabaseRow:row]];

    // This appears to be the best way to get an unsigned long long out of a string.
    ckme.wasCurrent = [[[[NSNumberFormatter alloc] init] numberFromString:row[@"wascurrent"].asString] unsignedLongLongValue];
    return ckme;
}

+ (NSDictionary<NSString*,NSNumber*>*)countsByParentKeyWithContextID:(NSString*)contextID
                                                              zoneID:(CKRecordZoneID*)zoneID
                                                               error:(NSError * __autoreleasing *)error
{
    NSMutableDictionary* results = [[NSMutableDictionary alloc] init];

    [CKKSSQLDatabaseObject queryDatabaseTable: [[self class] sqlTable]
                                        where: @{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone": CKKSNilToNSNull(zoneID.zoneName)
    }
                                      columns: @[@"parentKeyUUID", @"count(rowid)"]
                                      groupBy: @[@"parentKeyUUID"]
                                      orderBy:nil
                                        limit: -1
                                   processRow: ^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
                                       results[row[@"parentKeyUUID"].asString] = row[@"count(rowid)"].asNSNumberInteger;
                                   }
                                        error: error];
    return results;
}

+ (NSDictionary<NSString*,NSNumber*>*)countsByZoneNameWithContextID:(NSString*)contextID
                                                              error:(NSError * __autoreleasing *)error
{
    NSMutableDictionary* results = [[NSMutableDictionary alloc] init];

    [CKKSSQLDatabaseObject queryDatabaseTable:[[self class] sqlTable]
                                        where:@{
        @"contextID": CKKSNilToNSNull(contextID),
    }
                                      columns:@[@"ckzone", @"count(rowid)"]
                                      groupBy:@[@"ckzone"]
                                      orderBy:nil
                                        limit:-1
                                   processRow:^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
        results[row[@"ckzone"].asString] = row[@"count(rowid)"].asNSNumberInteger;
    }
                                        error: error];
    return results;
}

+ (NSNumber* _Nullable)countsWithContextID:(NSString*)contextID
                                    zoneID:(CKRecordZoneID*)zoneID
                                     error:(NSError * __autoreleasing *)error
{
    __block NSNumber *result = nil;

    [CKKSSQLDatabaseObject queryDatabaseTable: [[self class] sqlTable]
                                        where: @{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone": CKKSNilToNSNull(zoneID.zoneName)
    }
                                      columns: @[@"count(rowid)"]
                                      groupBy:nil
                                      orderBy:nil
                                        limit: -1
                                   processRow: ^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
                                       result = row[@"count(rowid)"].asNSNumberInteger;
                                   }
                                        error: error];
    return result;
}

+ (NSArray<NSData*>*)pcsMirrorKeysForService:(NSNumber*)service matchingKeys:(NSArray<NSData*>*)matchingKeys error:(NSError * __autoreleasing *)error
{
    NSMutableArray<NSData*>* mirrorKeys = [[NSMutableArray alloc] initWithCapacity:matchingKeys.count];

    [CKKSSQLDatabaseObject queryDatabaseTable:[self sqlTable]
                                        where:@{ @"pcss" : service }
                                      columns:@[ @"pcsk" ]
                                      groupBy:nil
                                      orderBy:@[ @"pcsk" ]
                                        limit:0
                                   processRow:^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
                                                  NSData *pcsk = row[@"pcsk"].asBase64DecodedData;
                                                  if ([matchingKeys containsObject:pcsk]) {
                                                      [mirrorKeys addObject:pcsk];
                                                  }
                                              }
                                        error:error];
    return mirrorKeys;
}

@end

#endif
