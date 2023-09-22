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
#ifndef SFAnalyticsSampler_h
#define SFAnalyticsSampler_h

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SFAnalyticsSampler : NSObject

@property (nonatomic) NSTimeInterval samplingInterval;
@property (nonatomic, readonly) NSString* name;
@property (nonatomic, readonly) BOOL oncePerReport;

- (instancetype)init NS_UNAVAILABLE;
- (NSNumber*)sampleNow;
- (void)pauseSampling;
- (void)resumeSampling;

@end

NS_ASSUME_NONNULL_END

#endif
#endif
