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

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@protocol supdProtocol
- (void)getSysdiagnoseDumpWithReply:(void (^)(NSString*_Nullable))reply;
- (void)createLoggingJSON:(bool)pretty topic:(NSString *)topicName reply:(void (^)(NSData *_Nullable, NSError*_Nullable))reply;
- (void)createChunkedLoggingJSON:(bool)pretty topic:(NSString *)topicName reply:(void (^)(NSData *_Nullable, NSError*_Nullable))reply;
- (void)forceUploadWithReply:(void (^)(BOOL, NSError*))reply;
- (void)setUploadDateWith:(NSDate *)date reply:(void (^)(BOOL, NSError*_Nullable))reply;
- (void)clientStatus:(void (^)(NSDictionary<NSString *, id> *_Nullable, NSError*_Nullable))reply;

- (void)getSFACollectionForCollection:(NSString *)client
                                reply:(void (^)(NSData *_Nullable, NSError *_Nullable))reply;
- (void)setSFACollection:(NSData *_Nullable)collection
                forTopic:(NSString *)topic
                   reply:(void (^)(NSError *_Nullable))reply;

@end

NS_ASSUME_NONNULL_END
