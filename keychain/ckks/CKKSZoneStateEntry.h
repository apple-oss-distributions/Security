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

#include "keychain/securityd/SecDbItem.h"
#include "utilities/SecDb.h"
#import "CKKSSQLDatabaseObject.h"

#ifndef CKKSZoneStateEntry_h
#define CKKSZoneStateEntry_h

#if OCTAGON

#import <CloudKit/CloudKit.h>
#import "keychain/ckks/CKKSFixups.h"

NS_ASSUME_NONNULL_BEGIN

/*
 * This class hold the state for a particular zone: has the zone been created, have we subscribed to it,
 * what's the current change token, etc.
 *
 * It also holds the zone's current "rate limiter" state. Currently, though, there is only a single, global
 * rate limiter. Therefore, each individual zone's state will have no data in the rate limiter slot, and we'll
 * create a global zone state entry holding the global rate limiter state. This split behavior allows us to bring
 * up zone-specific rate limiters under the global rate limiter later without database changes, if we decide 
 * that's useful.
 */

@class CKKSRateLimiter;
@interface CKKSZoneStateEntry : CKKSSQLDatabaseObject

@property (readonly) NSString* contextID;
@property NSString* ckzone;
@property bool ckzonecreated;
@property bool ckzonesubscribed;
@property (nullable, getter=getChangeToken, setter=setChangeToken:) CKServerChangeToken* changeToken;
@property (nullable) NSData* encodedChangeToken;
@property BOOL moreRecordsInCloudKit;
@property (nullable) NSDate* lastFetchTime;
@property (nullable) NSDate* lastLocalKeychainScanTime;
@property BOOL fetchNewestChangesFirst;
@property BOOL initialSyncFinished;

@property CKKSFixup lastFixup;


@property (nullable) CKKSRateLimiter* rateLimiter;
@property (nullable) NSData* encodedRateLimiter;

+ (instancetype)contextID:(NSString*)contextID
             zoneName:(NSString*)ckzone;

+ (instancetype)fromDatabase:(NSString*)contextID
                    zoneName:(NSString*)ckzone
                       error:(NSError* __autoreleasing*)error;

+ (instancetype)tryFromDatabase:(NSString*)contextID
                       zoneName:(NSString*)ckzone
                          error:(NSError* __autoreleasing*)error;

- (instancetype)initWithContextID:(NSString*)contextID
                         zoneName:(NSString*)ckzone
                      zoneCreated:(bool)ckzonecreated
                   zoneSubscribed:(bool)ckzonesubscribed
                      changeToken:(NSData* _Nullable)changetoken
            moreRecordsInCloudKit:(BOOL)moreRecords
                        lastFetch:(NSDate* _Nullable)lastFetch
                         lastScan:(NSDate* _Nullable)localKeychainScanned
                        lastFixup:(CKKSFixup)lastFixup
               encodedRateLimiter:(NSData* _Nullable)encodedRateLimiter
          fetchNewestChangesFirst:(BOOL)fetchNewestChangesFirst
              initialSyncFinished:(BOOL)initialSyncFinished;

- (CKServerChangeToken* _Nullable)getChangeToken;
- (void)setChangeToken:(CKServerChangeToken* _Nullable)token;

- (BOOL)isEqual:(id)object;
@end

NS_ASSUME_NONNULL_END
#endif
#endif /* CKKSZoneStateEntry_h */
