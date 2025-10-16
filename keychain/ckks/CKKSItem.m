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
#import "CKKSItem.h"
#import "CKKSSIV.h"

#include <utilities/SecDb.h>
#include "keychain/securityd/SecDbItem.h"
#include "keychain/securityd/SecItemSchema.h"

#import <CloudKit/CloudKit.h>
#import <CloudKit/CloudKit_Private.h>

#import "keychain/categories/NSError+UsefulConstructors.h"
#import "keychain/ckks/CKKSMirrorEntry.h"
#import "keychain/ckks/CKKSIncomingQueueEntry.h"
#import "keychain/ckks/CKKSOutgoingQueueEntry.h"

@implementation CKKSItem

- (instancetype) initWithCKRecord:(CKRecord*)record
                        contextID:(NSString*)contextID
{
    if(self = [super initWithCKRecord:record
                            contextID:contextID]) {
    }
    return self;
}

- (instancetype) initCopyingCKKSItem: (CKKSItem*) item {
    if(self = [super initWithCKRecordType:item.ckRecordType
                          encodedCKRecord:item.encodedCKRecord
                                contextID:item.contextID
                                   zoneID:item.zoneID]) {
        _uuid = item.uuid;
        _parentKeyUUID = item.parentKeyUUID;
        _generationCount = item.generationCount;
        _encitem = item.encitem;
        _wrappedkey = item.wrappedkey;
        _encver = item.encver;

        _plaintextPCSServiceIdentifier = item.plaintextPCSServiceIdentifier;
        _plaintextPCSPublicKey         = item.plaintextPCSPublicKey;
        _plaintextPCSPublicIdentity    = item.plaintextPCSPublicIdentity;
    }
    return self;
}

- (instancetype) initWithUUID: (NSString*) uuid
                parentKeyUUID: (NSString*) parentKeyUUID
                    contextID:(NSString*)contextID
                       zoneID: (CKRecordZoneID*) zoneID
{
    return [self initWithUUID:uuid
                parentKeyUUID:parentKeyUUID
                    contextID:contextID
                       zoneID:zoneID
              encodedCKRecord:nil
                      encItem:nil
                   wrappedkey:nil
              generationCount:0
                       encver:CKKSItemEncryptionVersionNone];
}

- (instancetype) initWithUUID: (NSString*) uuid
                parentKeyUUID: (NSString*) parentKeyUUID
                    contextID:(NSString*)contextID
                       zoneID: (CKRecordZoneID*) zoneID
                      encItem: (NSData*) encitem
                   wrappedkey: (CKKSWrappedAESSIVKey*) wrappedkey
              generationCount: (NSUInteger) genCount
                       encver: (NSUInteger) encver
{
    return [self initWithUUID:uuid
                parentKeyUUID:parentKeyUUID
                    contextID:contextID
                       zoneID:zoneID
              encodedCKRecord:nil
                      encItem:encitem
                   wrappedkey:wrappedkey
              generationCount:genCount
                       encver:encver];
}

- (instancetype) initWithUUID: (NSString*) uuid
                parentKeyUUID: (NSString*) parentKeyUUID
                    contextID:(NSString*)contextID
                       zoneID: (CKRecordZoneID*)zoneID
              encodedCKRecord: (NSData*) encodedrecord
                      encItem: (NSData*) encitem
                   wrappedkey: (CKKSWrappedAESSIVKey*) wrappedkey
              generationCount: (NSUInteger) genCount
                       encver: (NSUInteger) encver
{
    return [self initWithUUID:uuid
                parentKeyUUID:parentKeyUUID
                    contextID:contextID
                       zoneID:zoneID
              encodedCKRecord:encodedrecord
                      encItem:encitem
                   wrappedkey:wrappedkey
              generationCount:genCount
                       encver:encver
plaintextPCSServiceIdentifier:nil
        plaintextPCSPublicKey:nil
   plaintextPCSPublicIdentity:nil];
}

- (instancetype) initWithUUID: (NSString*) uuid
                parentKeyUUID: (NSString*) parentKeyUUID
                    contextID:(NSString*)contextID
                       zoneID: (CKRecordZoneID*)zoneID
              encodedCKRecord: (NSData*) encodedrecord
                      encItem: (NSData*) encitem
                   wrappedkey: (CKKSWrappedAESSIVKey*) wrappedkey
              generationCount: (NSUInteger) genCount
                       encver: (NSUInteger) encver
plaintextPCSServiceIdentifier: (NSNumber*) pcsServiceIdentifier
        plaintextPCSPublicKey: (NSData*) pcsPublicKey
   plaintextPCSPublicIdentity: (NSData*) pcsPublicIdentity
{
    if(self = [super initWithCKRecordType:SecCKRecordItemType
                          encodedCKRecord:encodedrecord
                                contextID:contextID
                                   zoneID:zoneID]) {
        _uuid = uuid;
        _parentKeyUUID = parentKeyUUID;
        _generationCount = genCount;
        self.encitem = encitem;
        _wrappedkey = wrappedkey;
        _encver = encver;

        _plaintextPCSServiceIdentifier = pcsServiceIdentifier;
        _plaintextPCSPublicKey = pcsPublicKey;
        _plaintextPCSPublicIdentity = pcsPublicIdentity;
    }

    return self;
}

- (BOOL)isEqual: (id) object {
    if(![object isKindOfClass:[CKKSItem class]]) {
        return NO;
    }

    CKKSItem* obj = (CKKSItem*) object;

    return ([self.uuid isEqual: obj.uuid] &&
            [self.parentKeyUUID isEqual: obj.parentKeyUUID] &&
            [self.zoneID isEqual: obj.zoneID] &&
            ((self.contextID == nil && obj.contextID == nil) || ([self.contextID isEqualToString:obj.contextID])) &&
            ((self.encitem == nil && obj.encitem == nil) || ([self.encitem isEqual: obj.encitem])) &&
            [self.wrappedkey isEqual: obj.wrappedkey] &&
            self.generationCount == obj.generationCount &&
            self.encver == obj.encver &&
            true) ? YES : NO;
}

#pragma mark - CKRecord handling

- (NSString*) CKRecordName {
    return self.uuid;
}

- (void) setFromCKRecord: (CKRecord*) record {
    if(![record.recordType isEqual: SecCKRecordItemType]) {
        @throw [NSException
                exceptionWithName:@"WrongCKRecordTypeException"
                reason:[NSString stringWithFormat: @"CKRecordType (%@) was not %@", record.recordType, SecCKRecordItemType]
                userInfo:nil];
    }

    [self setStoredCKRecord:record];

    _uuid = [[record recordID] recordName];
    self.parentKeyUUID = [record[SecCKRecordParentKeyRefKey] recordID].recordName;
    self.encitem = record[SecCKRecordDataKey];

    // If wrapped key is nil, this is a bad record. We've seen this at least once, though, and so need to be resilient to it.
    // Passing nil here will cause a crash, so pass all zeroes.
    NSString* wrappedKey = record[SecCKRecordWrappedKeyKey];
    if(wrappedKey) {
        self.wrappedkey = [[CKKSWrappedAESSIVKey alloc] initWithBase64:wrappedKey];
    } else {
        ckkserror("ckksitem", record.recordID.zoneID, "Corrupt item recieved with no wrapped key");
        self.wrappedkey = [CKKSWrappedAESSIVKey zeroedKey];
    }

    self.generationCount = [record[SecCKRecordGenerationCountKey] unsignedIntegerValue];
    self.encver = [record[SecCKRecordEncryptionVersionKey] unsignedIntegerValue];

    self.plaintextPCSServiceIdentifier = record[SecCKRecordPCSServiceIdentifier];
    self.plaintextPCSPublicKey         = record[SecCKRecordPCSPublicKey];
    self.plaintextPCSPublicIdentity    = record[SecCKRecordPCSPublicIdentity];
}

+ (void)setOSVersionInRecord: (CKRecord*) record {
     record[SecCKRecordHostOSVersionKey] = SecCKKSHostOSVersion();
}

- (CKRecord*) updateCKRecord: (CKRecord*) record zoneID: (CKRecordZoneID*) zoneID {
    if(![record.recordType isEqual: SecCKRecordItemType]) {
        @throw [NSException
                exceptionWithName:@"WrongCKRecordTypeException"
                reason:[NSString stringWithFormat: @"CKRecordType (%@) was not %@", record.recordType, SecCKRecordItemType]
                userInfo:nil];
    }

    // Items must have a wrapping key.
    record[SecCKRecordParentKeyRefKey] = [[CKReference alloc] initWithRecordID: [[CKRecordID alloc] initWithRecordName: self.parentKeyUUID zoneID: zoneID] action: CKReferenceActionValidate];

    [CKKSItem setOSVersionInRecord: record];

    record[SecCKRecordDataKey] = self.encitem;
    record[SecCKRecordWrappedKeyKey] = [self.wrappedkey base64WrappedKey];
    record[SecCKRecordGenerationCountKey] = [NSNumber numberWithInteger:self.generationCount];
    // TODO: if the record's generation count is already higher than ours, that's a problem.
    record[SecCKRecordEncryptionVersionKey] = [NSNumber numberWithInteger:self.encver];

    // Add unencrypted fields
    record[SecCKRecordPCSServiceIdentifier] = self.plaintextPCSServiceIdentifier;
    record[SecCKRecordPCSPublicKey]         = self.plaintextPCSPublicKey;
    record[SecCKRecordPCSPublicIdentity]    = self.plaintextPCSPublicIdentity;

    return record;
}


- (bool) matchesCKRecord: (CKRecord*) record {
    if(![record.recordType isEqual: SecCKRecordItemType]) {
        return false;
    }

    // We only really care about the data, the wrapped key, the generation count, and the parent key.
    // Note that since all of those things are included as authenticated data into the AES-SIV ciphertext, we could just
    // compare that. However, check 'em all.
    if(![record.recordID.recordName isEqualToString: self.uuid]) {
        ckksinfo_global("ckksitem", "UUID does not match");
        return false;
    }

    if(![[record[SecCKRecordParentKeyRefKey] recordID].recordName isEqualToString: self.parentKeyUUID]) {
        ckksinfo_global("ckksitem", "wrapping key reference does not match");
        return false;
    }

    if(![record[SecCKRecordGenerationCountKey] isEqual: [NSNumber numberWithInteger:self.generationCount]]) {
        ckksinfo_global("ckksitem", "SecCKRecordGenerationCountKey does not match");
        return false;
    }

    if(![record[SecCKRecordWrappedKeyKey] isEqual: [self.wrappedkey base64WrappedKey]]) {
        ckksinfo_global("ckksitem", "SecCKRecordWrappedKeyKey does not match");
        return false;
    }

    if(![record[SecCKRecordDataKey] isEqual: self.encitem]) {
        ckksinfo_global("ckksitem", "SecCKRecordDataKey does not match");
        return false;
    }

    // Compare plaintext records, too
    // Why is obj-c nullable equality so difficult?
    if(!((record[SecCKRecordPCSServiceIdentifier] == nil && self.plaintextPCSServiceIdentifier == nil) ||
          [record[SecCKRecordPCSServiceIdentifier] isEqual: self.plaintextPCSServiceIdentifier])) {
        ckksinfo_global("ckksitem", "SecCKRecordPCSServiceIdentifier does not match");
        return false;
    }

    if(!((record[SecCKRecordPCSPublicKey] == nil && self.plaintextPCSPublicKey == nil) ||
          [record[SecCKRecordPCSPublicKey] isEqual: self.plaintextPCSPublicKey])) {
        ckksinfo_global("ckksitem", "SecCKRecordPCSPublicKey does not match");
        return false;
    }

    if(!((record[SecCKRecordPCSPublicIdentity] == nil && self.plaintextPCSPublicIdentity == nil) ||
          [record[SecCKRecordPCSPublicIdentity] isEqual: self.plaintextPCSPublicIdentity])) {
        ckksinfo_global("ckksitem", "SecCKRecordPCSPublicIdentity does not match");
        return false;
    }

    return true;
}

// Generates the list of 'authenticated data' to go along with this item, and optionally adds in unknown, future fields received from CloudKit
- (NSDictionary<NSString*, NSData*>*)makeAuthenticatedDataDictionaryUpdatingCKKSItem:(CKKSItem*) olditem encryptionVersion:(SecCKKSItemEncryptionVersion)encversion {
    switch(encversion) {
        case CKKSItemEncryptionVersion1:
            return [self makeAuthenticatedDataDictionaryUpdatingCKKSItemEncVer1];
        case CKKSItemEncryptionVersion2:
            return [self makeAuthenticatedDataDictionaryUpdatingCKKSItemEncVer2:olditem];
        default:
            @throw [NSException
                    exceptionWithName:@"WrongEncryptionVersionException"
                    reason:[NSString stringWithFormat: @"%d is not a known encryption version", (int)encversion]
                    userInfo:nil];
    }
}

- (NSDictionary<NSString*, NSData*>*)makeAuthenticatedDataDictionaryUpdatingCKKSItemEncVer1 {
    NSMutableDictionary<NSString*, NSData*>* authenticatedData = [[NSMutableDictionary alloc] init];

    authenticatedData[@"UUID"] = [self.uuid dataUsingEncoding: NSUTF8StringEncoding];
    authenticatedData[SecCKRecordWrappedKeyKey] = [self.parentKeyUUID dataUsingEncoding: NSUTF8StringEncoding];

    uint64_t genCount64 = OSSwapHostToLittleConstInt64(self.generationCount);
    authenticatedData[SecCKRecordGenerationCountKey] = [NSData dataWithBytes:&genCount64 length:sizeof(genCount64)];

    uint64_t encver = OSSwapHostToLittleConstInt64((uint64_t)self.encver);
    authenticatedData[SecCKRecordEncryptionVersionKey] = [NSData dataWithBytes:&encver length:sizeof(encver)];

    // In v1, don't authenticate the plaintext PCS fields
    authenticatedData[SecCKRecordPCSServiceIdentifier] = nil;
    authenticatedData[SecCKRecordPCSPublicKey]         = nil;
    authenticatedData[SecCKRecordPCSPublicIdentity]    = nil;

    return authenticatedData;
}

- (NSDictionary<NSString*, NSData*>*)makeAuthenticatedDataDictionaryUpdatingCKKSItemEncVer2:(CKKSItem*) olditem {
    NSMutableDictionary<NSString*, NSData*>* authenticatedData = [[NSMutableDictionary alloc] init];

    authenticatedData[@"UUID"] = [self.uuid dataUsingEncoding: NSUTF8StringEncoding];
    authenticatedData[SecCKRecordWrappedKeyKey] = [self.parentKeyUUID dataUsingEncoding: NSUTF8StringEncoding];

    uint64_t genCount64 = OSSwapHostToLittleConstInt64(self.generationCount);
    authenticatedData[SecCKRecordGenerationCountKey] = [NSData dataWithBytes:&genCount64 length:sizeof(genCount64)];

    uint64_t encver = OSSwapHostToLittleConstInt64((uint64_t)self.encver);
    authenticatedData[SecCKRecordEncryptionVersionKey] = [NSData dataWithBytes:&encver length:sizeof(encver)];

    // v2 authenticates the PCS fields too
    if(self.plaintextPCSServiceIdentifier) {
        uint64_t pcsServiceIdentifier = OSSwapHostToLittleConstInt64([self.plaintextPCSServiceIdentifier unsignedLongValue]);
        authenticatedData[SecCKRecordPCSServiceIdentifier] = [NSData dataWithBytes:&pcsServiceIdentifier length:sizeof(pcsServiceIdentifier)];
    }
    authenticatedData[SecCKRecordPCSPublicKey]         = self.plaintextPCSPublicKey;
    authenticatedData[SecCKRecordPCSPublicIdentity]    = self.plaintextPCSPublicIdentity;

    // Iterate through the fields in the old CKKSItem. If we don't recognize any of them, add them to the authenticated data.
    if(olditem) {
        CKRecord* record = olditem.storedCKRecord;
        if(record) {
            for(NSString* key in record.allKeys) {
                if([key isEqualToString:@"UUID"] ||
                   [key isEqualToString:SecCKRecordHostOSVersionKey] ||
                   [key isEqualToString:SecCKRecordDataKey] ||
                   [key isEqualToString:SecCKRecordWrappedKeyKey] ||
                   [key isEqualToString:SecCKRecordGenerationCountKey] ||
                   [key isEqualToString:SecCKRecordEncryptionVersionKey] ||
                   [key isEqualToString:SecCKRecordPCSServiceIdentifier] ||
                   [key isEqualToString:SecCKRecordPCSPublicKey] ||
                   [key isEqualToString:SecCKRecordPCSPublicIdentity]) {
                    // This version of CKKS knows about this data field. Ignore them with prejudice.
                    continue;
                }

                if([key hasPrefix:@"server_"]) {
                    // Ignore all fields prefixed by "server_"
                    continue;
                }

                id obj = record[key];

                // Skip CKReferences, NSArray, CLLocation, and CKAsset.
                if([obj isKindOfClass: [NSString class]]) {
                    // Add an NSString.
                    authenticatedData[key] = [obj dataUsingEncoding: NSUTF8StringEncoding];
                } else if([obj isKindOfClass: [NSData class]]) {
                    // Add an NSData
                    authenticatedData[key] = [obj copy];
                } else if([obj isKindOfClass:[NSDate class]]) {
                    // Add an NSDate
                    NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
                    NSString* str = [formatter stringForObjectValue: obj];

                    authenticatedData[key] = [str dataUsingEncoding: NSUTF8StringEncoding];
                } else if([obj isKindOfClass: [NSNumber class]]) {
                    // Add an NSNumber
                    uint64_t n64 = OSSwapHostToLittleConstInt64([obj unsignedLongLongValue]);
                    authenticatedData[key] = [NSData dataWithBytes:&n64 length:sizeof(n64)];
                }
            }

        }
    }

    // TODO: add unauth'ed field name here

    return authenticatedData;
}

#pragma mark - Utility

- (NSString*)description {
    return [NSString stringWithFormat: @"<%@: %@>", NSStringFromClass([self class]), self.uuid];
}

- (NSString*)debugDescription {
    return [NSString stringWithFormat: @"<%@: %@ %p>", NSStringFromClass([self class]), self.uuid, self];
}

- (instancetype)copyWithZone:(NSZone *)zone {
    CKKSItem *itemCopy = [super copyWithZone:zone];
    itemCopy->_uuid = _uuid;
    itemCopy->_parentKeyUUID = _parentKeyUUID;
    itemCopy->_encitem = _encitem;
    itemCopy->_wrappedkey = _wrappedkey;
    itemCopy->_generationCount = _generationCount;
    itemCopy->_encver = _encver;
    return itemCopy;
}

#pragma mark - Getters/Setters

- (NSString*) base64Item {
    return [self.encitem base64EncodedStringWithOptions:0];
}

- (void) setBase64Item: (NSString*) base64Item {
    _encitem = [[NSData alloc] initWithBase64EncodedString: base64Item options:0];
}

#pragma mark - CKKSSQLDatabaseObject helpers

// Note that CKKSItems are not intended to be saved directly, and so CKKSItem does not implement sqlTable.
// You must subclass CKKSItem to have this work correctly, although you can call back up into this class to use these if you like.

+ (NSArray<NSString*>*)sqlColumns {
    return @[@"contextID", @"UUID", @"parentKeyUUID", @"ckzone", @"encitem", @"wrappedkey", @"gencount", @"encver", @"ckrecord",
             @"pcss", @"pcsk", @"pcsi"];
}

- (NSDictionary<NSString*,NSString*>*)whereClauseToFindSelf {
    return @{
        @"contextID": CKKSNilToNSNull(self.contextID),
        @"UUID": self.uuid,
        @"ckzone":self.zoneID.zoneName
    };
}

- (NSDictionary<NSString*,NSString*>*)sqlValues {
    return @{
        @"contextID": CKKSNilToNSNull(self.contextID),
        @"UUID": self.uuid,
        @"parentKeyUUID": self.parentKeyUUID,
        @"ckzone":  CKKSNilToNSNull(self.zoneID.zoneName),
        @"encitem": self.base64encitem,
        @"wrappedkey": [self.wrappedkey base64WrappedKey],
        @"gencount": [[NSNumber numberWithInteger:self.generationCount] stringValue],
        @"encver": [[NSNumber numberWithInteger:self.encver] stringValue],
        @"ckrecord": CKKSNilToNSNull([self.encodedCKRecord base64EncodedStringWithOptions:0]),
        @"pcss": CKKSNilToNSNull(self.plaintextPCSServiceIdentifier),
        @"pcsk": CKKSNilToNSNull([self.plaintextPCSPublicKey base64EncodedStringWithOptions:0]),
        @"pcsi": CKKSNilToNSNull([self.plaintextPCSPublicIdentity base64EncodedStringWithOptions:0])
    };
}

+ (instancetype)fromDatabaseRow:(NSDictionary<NSString*, CKKSSQLResult*>*)row {
    return [[CKKSItem alloc] initWithUUID:row[@"UUID"].asString
                            parentKeyUUID:row[@"parentKeyUUID"].asString
                                contextID:row[@"contextID"].asString
                                   zoneID:[[CKRecordZoneID alloc] initWithZoneName: row[@"ckzone"].asString ownerName:CKCurrentUserDefaultName]
                          encodedCKRecord:row[@"ckrecord"].asBase64DecodedData
                                  encItem:row[@"encitem"].asBase64DecodedData
                               wrappedkey:row[@"wrappedkey"].asString == nil ? nil : [[CKKSWrappedAESSIVKey alloc] initWithBase64:row[@"wrappedkey"].asString]
                          generationCount:row[@"gencount"].asNSInteger
                                   encver:row[@"encver"].asNSInteger
            plaintextPCSServiceIdentifier:row[@"pcss"].asNSNumberInteger
                    plaintextPCSPublicKey:row[@"pcsk"].asBase64DecodedData
               plaintextPCSPublicIdentity:row[@"pcsi"].asBase64DecodedData
            ];
}

+ (BOOL)intransactionRecordChanged:(CKRecord*)record
                         contextID:(NSString*)contextID
                            resync:(BOOL)resync
                             error:(NSError**)error
{
    NSError* localerror = nil;
    // Find if we knew about this record in the past
    bool update = false;
    CKKSMirrorEntry* ckme = [CKKSMirrorEntry tryFromDatabase:[[record recordID] recordName]
                                                   contextID:contextID
                                                      zoneID:record.recordID.zoneID
                                                       error:&localerror];

    if(localerror) {
        ckkserror("ckks", record.recordID.zoneID, "error loading a CKKSMirrorEntry from database: %@", localerror);
        if(error) {
            *error = localerror;
        }
        return NO;
    }

    if(resync) {
        if(!ckme) {
            ckkserror("ckksresync", record.recordID.zoneID, "BUG: No local item matching resynced CloudKit record: %@", record);
        } else if(![ckme matchesCKRecord:record]) {
            ckkserror("ckksresync", record.recordID.zoneID, "BUG: Local item doesn't match resynced CloudKit record: %@ %@", ckme, record);
        } else {
            ckksnotice("ckksresync", record.recordID.zoneID, "Already know about this item record, updating anyway: %@", record.recordID);
        }
    }

    if(ckme && ckme.item && ckme.item.generationCount > [record[SecCKRecordGenerationCountKey] unsignedLongLongValue]) {
        ckkserror("ckks", record.recordID.zoneID, "received a record from CloudKit with a bad generation count: %@ (%ld > %@)", ckme.uuid,
                 (long) ckme.item.generationCount,
                 record[SecCKRecordGenerationCountKey]);

        if(error) {
            *error = [NSError errorWithDomain:CKKSErrorDomain
                                         code:CKKSErrorGenerationCountMismatch
                                  description:[NSString stringWithFormat:@"Received a record(%@) with a bad generation count (%ld > %@)",
                                               ckme.uuid,
                                               (long) ckme.item.generationCount,
                                               record[SecCKRecordGenerationCountKey]]];
        }
        // Abort processing this record.
        return NO;
    }

    // If we found an old version in the database; this might be an update
    if(ckme) {
        if([ckme matchesCKRecord:record] && !resync) {
            // This is almost certainly a record we uploaded; CKFetchChanges sends them back as new records
            ckksnotice("ckks", record.recordID.zoneID, "CloudKit has told us of record we already know about for %@; skipping update", ckme.uuid);
            return YES;
        }

        update = true;
        // Set the CKKSMirrorEntry's fields to be whatever this record holds
        [ckme setFromCKRecord: record];
    } else {
        // Have to make a new CKKSMirrorEntry
        ckme = [[CKKSMirrorEntry alloc] initWithCKRecord:record contextID:contextID];
    }

    bool mirrorsaved = [ckme saveToDatabase:&localerror];

    if(!mirrorsaved || localerror) {
        ckkserror("ckks", record.recordID.zoneID, "couldn't save new CKRecord to database: %@ %@", record, localerror);
        if(error) {
            *error = localerror;
        }
        return NO;
    } else {
        ckksinfo("ckks", record.recordID.zoneID, "CKKSMirrorEntry was created: %@", ckme);
    }

    // A remote change has occurred for this UUID. Delete any pending IQEs, in any state.
    NSError* iqeLoadError = nil;
    CKKSIncomingQueueEntry* loadediqe = [CKKSIncomingQueueEntry tryFromDatabase:ckme.item.uuid
                                                                      contextID:contextID
                                                                         zoneID:ckme.item.zoneID
                                                                          error:&iqeLoadError];
    if(iqeLoadError) {
        ckkserror("ckks", record.recordID.zoneID, "Couldn't load possible existing incoming queue entry: %@", iqeLoadError);
    }
    if(loadediqe) {
        ckksnotice("ckks", record.recordID.zoneID, "Deleting existing CKKSIncomingQueueEntry: %@", loadediqe);

        NSError* iqeDeleteError = nil;
        [loadediqe deleteFromDatabase:&iqeDeleteError];

        if(iqeDeleteError) {
            ckkserror("ckks", record.recordID.zoneID, "Couldn't delete existing incoming queue entry: %@", iqeDeleteError);
        }
    }

    NSError* iqeerror = nil;
    CKKSIncomingQueueEntry* iqe = [[CKKSIncomingQueueEntry alloc] initWithCKKSItem:ckme.item
                                                                            action:(update ? SecCKKSActionModify : SecCKKSActionAdd)
                                                                             state:SecCKKSStateNew];
    bool iqesaved = [iqe saveToDatabase:&iqeerror];
    if(!iqesaved || iqeerror) {
        ckkserror("ckks", record.recordID.zoneID, "Couldn't save modified incoming queue entry: %@", iqeerror);
        if(error) {
            *error = iqeerror;
        }
        return NO;
    } else {
        ckksinfo("ckks", record.recordID.zoneID, "CKKSIncomingQueueEntry was created: %@", iqe);
    }

    // A remote change has occured for this record. Delete any pending local changes; they will be overwritten.
    NSArray<CKKSOutgoingQueueEntry*>* siblings = [CKKSOutgoingQueueEntry allWithUUID:iqe.uuid
                                                                              states:@[SecCKKSStateNew,
                                                                                       SecCKKSStateReencrypt,
                                                                                       SecCKKSStateError]
                                                                           contextID:contextID
                                                                              zoneID:record.recordID.zoneID
                                                                               error:&localerror];
    if(!siblings || localerror) {
        ckkserror("ckks", record.recordID.zoneID, "Couldn't load OQE sibling for %@: %@", iqe.uuid, localerror);
    }

    for(CKKSOutgoingQueueEntry* oqe in siblings) {
        NSError* deletionError = nil;
        [oqe deleteFromDatabase:&deletionError];
        if(deletionError) {
            ckkserror("ckks", record.recordID.zoneID, "Couldn't delete OQE sibling(%@) for %@: %@", oqe, iqe.uuid, deletionError);
            if(error) {
                *error = deletionError;
            }
            return NO;
        }
    }

    return YES;
}


+ (BOOL)intransactionRecordDeleted:(CKRecordID*)recordID
                         contextID:(NSString*)contextID
                            resync:(BOOL)resync
                             error:(NSError**)error
{
    ckksnotice("ckks", recordID.zoneID, "CloudKit notification: deleted record(%@): %@", SecCKRecordItemType, recordID);
    NSError* iqeerror = nil;
    CKKSMirrorEntry* ckme = [CKKSMirrorEntry tryFromDatabase:recordID.recordName
                                                   contextID:contextID
                                                      zoneID:recordID.zoneID
                                                       error:error];

    // Deletes always succeed, not matter the generation count
    if(ckme) {
        NSError* localerror = nil;
        if(![ckme deleteFromDatabase:&localerror]) {
            if(error) {
                *error = localerror;
            }
            return NO;
        }

        CKKSIncomingQueueEntry* iqe = [[CKKSIncomingQueueEntry alloc] initWithCKKSItem:ckme.item action:SecCKKSActionDelete state:SecCKKSStateNew];
        [iqe saveToDatabase:&iqeerror];
        if(iqeerror) {
            ckkserror("ckks", recordID.zoneID, "Couldn't save incoming queue entry: %@", iqeerror);
            if(error) {
                *error = iqeerror;
            }
            return NO;
        }

        // Delete any pending local changes; this delete wins
        NSError* deleteError = nil;
        NSArray<CKKSOutgoingQueueEntry*>* siblings = [CKKSOutgoingQueueEntry allWithUUID:iqe.uuid
                                                                                  states:@[SecCKKSStateNew,
                                                                                           SecCKKSStateReencrypt,
                                                                                           SecCKKSStateError]
                                                                               contextID:contextID
                                                                                  zoneID:recordID.zoneID
                                                                                   error:&deleteError];
        if(deleteError) {
            ckkserror("ckks", recordID.zoneID, "Couldn't load OQE sibling for %@: %@", iqe.uuid, deleteError);
            if(error) {
                *error = deleteError;
            }
            return NO;
        }

        for(CKKSOutgoingQueueEntry* oqe in siblings) {
            NSError* deletionError = nil;
            [oqe deleteFromDatabase:&deletionError];
            if(deletionError) {
                ckkserror("ckks", recordID.zoneID, "Couldn't delete OQE sibling(%@) for %@: %@", oqe, iqe.uuid, deletionError);
                if(error) {
                    *error = deletionError;
                }
                return NO;
            }
        }
    }
    ckksinfo("ckks", recordID.zoneID, "CKKSMirrorEntry was deleted: %@ %@", recordID, ckme);
    return YES;
}


@end

#pragma mark - CK-Aware Database Helpers

@implementation CKKSSQLDatabaseObject (CKKSZoneExtras)

+ (NSSet<NSString*>*)allUUIDsWithContextID:(NSString*)contextID
                                   inZones:(NSSet<CKRecordZoneID*>*)zoneIDs
                                     error:(NSError * __autoreleasing *)error
{
    __block NSMutableSet<NSString*>* uuids = [NSMutableSet set];

    NSMutableArray<NSString*>* zoneNames = [NSMutableArray array];
    for(CKRecordZoneID* zoneID in zoneIDs) {
        [zoneNames addObject:zoneID.zoneName];
    }

    [CKKSSQLDatabaseObject queryDatabaseTable:[self sqlTable]
                                        where:@{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone": [[CKKSSQLWhereIn alloc] initWithValues:zoneNames]
    }
                                      columns:@[@"UUID"]
                                      groupBy:nil
                                      orderBy:nil
                                        limit:-1
                                   processRow:^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
                                       [uuids addObject:row[@"UUID"].asString];
                                   }
                                        error: error];
    return uuids;
}

+ (NSArray<NSString*>*)allUUIDsWithContextID:(NSString*)contextID
                                      zoneID:(CKRecordZoneID*)zoneID
                                       error:(NSError * __autoreleasing *)error {
    __block NSMutableArray<NSString*>* uuids = [[NSMutableArray alloc] init];

    [CKKSSQLDatabaseObject queryDatabaseTable: [self sqlTable]
                                        where:@{
                                            @"contextID": CKKSNilToNSNull(contextID),
                                            @"ckzone": CKKSNilToNSNull(zoneID.zoneName)
                                        }
                                        columns: @[@"UUID"]
                                        groupBy: nil
                                        orderBy:nil
                                        limit: -1
                                   processRow:^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
                                       [uuids addObject: row[@"UUID"].asString];
                                   }
                                        error: error];
    return uuids;
}

+ (NSSet<NSString*>*)allParentKeyUUIDsInContextID:(NSString*)contextID
                                           zoneID:(CKRecordZoneID*)zoneID
                                            error:(NSError * __autoreleasing *)error
{
    __block NSMutableSet<NSString*>* uuids = [NSMutableSet set];

    [CKKSSQLDatabaseObject queryDatabaseTable:[self sqlTable]
                                        where:@{
                                            @"contextID": CKKSNilToNSNull(contextID),
                                            @"ckzone": CKKSNilToNSNull(zoneID.zoneName)
                                        }
                                        columns:@[@"parentKeyUUID"]
                                        groupBy:nil
                                        orderBy:nil
                                        limit:-1
                                        processRow:^(NSDictionary<NSString*, CKKSSQLResult*>* row) {
                                            [uuids addObject:row[@"parentKeyUUID"].asString];
                                        }
                                        error: error];
    return uuids;
}

+ (NSArray*)allWithContextID:(NSString*)contextID
                      zoneID:(CKRecordZoneID*)zoneID
                       error:(NSError * __autoreleasing *)error
{
    return [self allWhere: @{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone": CKKSNilToNSNull(zoneID.zoneName)
    } error:error];
}

+ (NSArray*)allWithContextID:(NSString*)contextID
                       error:(NSError * __autoreleasing *)error
{
    return [self allWhere: @{
        @"contextID": CKKSNilToNSNull(contextID),
    } error:error];
}

+ (bool)deleteAllWithContextID:(NSString*)contextID
                        zoneID:(CKRecordZoneID*)zoneID
                         error:(NSError * __autoreleasing *)error
{
    bool ok = [CKKSSQLDatabaseObject deleteFromTable:[self sqlTable] where: @{
        @"contextID": CKKSNilToNSNull(contextID),
        @"ckzone":CKKSNilToNSNull(zoneID.zoneName)
    } connection:nil error: error];

    if(ok) {
        secdebug("ckksitem", "Deleted all %@", self);
    } else {
        secdebug("ckksitem", "Couldn't delete all %@: %@", self, error ? *error : @"unknown");
    }
    return ok;
}

+ (bool)deleteAllWithContextID:(NSString*)contextID
                         error:(NSError * __autoreleasing *)error
{
    bool ok = [CKKSSQLDatabaseObject deleteFromTable:[self sqlTable] where: @{
        @"contextID": CKKSNilToNSNull(contextID),
    } connection:nil error: error];

    if(ok) {
        secdebug("ckksitem", "Deleted all %@", self);
    } else {
        secdebug("ckksitem", "Couldn't delete all %@: %@", self, error ? *error : @"unknown");
    }
    return ok;
}

@end

#endif
