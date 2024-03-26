/*
 * Copyright (c) 2019 Apple Inc. All Rights Reserved.
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
#import "keychain/ot/OctagonStateMachineHelpers.h"
#import "OTDeviceInformation.h"
#import "keychain/ot/OTOperationDependencies.h"

NS_ASSUME_NONNULL_BEGIN

@class TrustedPeersHelperHealthCheckResult;

@interface OTCheckHealthOperation : CKKSGroupOperation <OctagonStateTransitionOperationProtocol>
@property OctagonState* nextState;

- (instancetype)init NS_UNAVAILABLE;

- (instancetype)initWithDependencies:(OTOperationDependencies*)dependencies
                       intendedState:(OctagonState*)intendedState
                          errorState:(OctagonState*)errorState
                          deviceInfo:(nonnull OTDeviceInformation *)deviceInfo
                skipRateLimitedCheck:(BOOL)skipRateLimitedCheck
             reportRateLimitingError:(BOOL)reportRateLimitingError
                              repair:(BOOL)repair;

@property OTDeviceInformation* deviceInfo;

@property (readonly) BOOL skipRateLimitingCheck;
@property (readonly) BOOL reportRateLimitingError;
@property (readonly) BOOL repair;

@property (nullable) TrustedPeersHelperHealthCheckResult* results;

@end

NS_ASSUME_NONNULL_END

#endif // OCTAGON
