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

#include "keychain/securityd/SecDbItem.h"
#include "utilities/SecDb.h"
#import "CKKSItem.h"
#import "CKKSSQLDatabaseObject.h"

#ifndef CKKSMirrorEntry_h
#define CKKSMirrorEntry_h

#import <CloudKit/CloudKit.h>

NS_ASSUME_NONNULL_BEGIN

@class CKKSWrappedAESSIVKey;

@interface CKKSMirrorEntry : CKKSSQLDatabaseObject

@property CKKSItem* item;
@property NSString* uuid;

@property uint64_t wasCurrent;

- (instancetype)initWithCKKSItem:(CKKSItem*)item;
- (instancetype)initWithCKRecord:(CKRecord*)record
                       contextID:(NSString*)contextID;
- (void)setFromCKRecord:(CKRecord*)record;
- (bool)matchesCKRecord:(CKRecord*)record;
- (bool)matchesCKRecord:(CKRecord*)record checkServerFields:(bool)checkServerFields;

+ (instancetype _Nullable)fromDatabase:(NSString*)uuid
                             contextID:(NSString*)contextID
                                zoneID:(CKRecordZoneID*)zoneID
                                 error:(NSError * __autoreleasing *)error;
+ (instancetype _Nullable)tryFromDatabase:(NSString*)uuid
                                contextID:(NSString*)contextID
                                   zoneID:(CKRecordZoneID*)zoneID
                                    error:(NSError * __autoreleasing *)error;

+ (NSArray<CKKSMirrorEntry*>*)allWithUUID:(NSString*)uuid
                                contextID:(NSString*)contextID
                                    error:(NSError**)error;

+ (NSDictionary<NSString*,NSNumber*>*)countsByParentKeyWithContextID:(NSString*)contextID
                                                              zoneID:(CKRecordZoneID*)zoneID
                                                               error:(NSError * __autoreleasing *)error;
+ (NSNumber* _Nullable)countsWithContextID:(NSString*)contextID
                                    zoneID:(CKRecordZoneID*)zoneID
                                     error:(NSError * __autoreleasing *)error;

+ (NSDictionary<NSString*,NSNumber*>*)countsByZoneNameWithContextID:(NSString*)contextID
                                                              error:(NSError * __autoreleasing *)error;

+ (NSArray<NSData*>*)pcsMirrorKeysForService:(NSNumber*)service
                                matchingKeys:(NSArray<NSData*>*)matchingKeys
                                       error:(NSError * __autoreleasing *)error;

@end

NS_ASSUME_NONNULL_END
#endif
#endif /* CKKSOutgoingQueueEntry_h */
