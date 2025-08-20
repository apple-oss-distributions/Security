/*
 * Copyright (c) 2018 Apple Inc. All Rights Reserved.
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

#ifndef KCJoiningAcceptSession_Internal_h
#define KCJoiningAcceptSession_Internal_h

#import <Foundation/Foundation.h>
#import "keychain/ot/OTControl.h"
#import <KeychainCircle/KCJoiningSession.h>

@interface KCJoiningAcceptSession (Internal)

- (KCAESGCMDuplexSession*)accessSession;

-(void)setControlObject:(OTControl*)control;
- (void)setSessionControlArguments:(OTControlArguments*)controlArguments;
- (void)setConfiguration:(OTJoiningConfiguration *)config;
- (void)setPiggybackingVersion:(uint64_t)version;
@end
#endif /* Header_h */
#endif
