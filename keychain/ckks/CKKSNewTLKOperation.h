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

#import <Foundation/Foundation.h>
#import "keychain/ckks/CKKSGroupOperation.h"
#import "keychain/ckks/CKKSProvideKeySetOperation.h"
#import "keychain/ckks/CKKSOperationDependencies.h"
#import "keychain/ot/OctagonStateMachine.h"

NS_ASSUME_NONNULL_BEGIN

@class CKKSKeychainView;

// This class will create+return the current key hierchies for all views

@interface CKKSNewTLKOperation : CKKSGroupOperation <OctagonStateTransitionOperationProtocol>
@property (readonly) CKKSOperationDependencies* deps;

@property (readonly, nullable) NSDictionary<CKRecordZoneID*, CKKSCurrentKeySet*>* keysets;

- (instancetype)init NS_UNAVAILABLE;

// Any non-pending keysets provided to preexistingPendingKeySets will be ignored
- (instancetype)initWithDependencies:(CKKSOperationDependencies*)dependencies
                    rollTLKIfPresent:(BOOL)rollTLKIfPresent
           preexistingPendingKeySets:(NSDictionary<CKRecordZoneID*, CKKSCurrentKeySet*>* _Nullable)previousPendingKeySets
                       intendedState:(CKKSState *)intendedState
                          errorState:(CKKSState *)errorState;

@end

NS_ASSUME_NONNULL_END

#endif  // OCTAGON
