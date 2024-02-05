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

#import "keychain/ot/OTJoiningConfiguration.h"

#if __OBJC2__

NS_ASSUME_NONNULL_BEGIN

@implementation OTJoiningConfiguration

+ (BOOL)supportsSecureCoding {
    return YES;
}

- (instancetype)initWithProtocolType:(NSString*)protocolType
                      uniqueDeviceID:(NSString*)uniqueDeviceID
                      uniqueClientID:(NSString*)uniqueClientID
                         pairingUUID:(NSString* _Nullable)pairingUUID
                               epoch:(uint64_t)epoch
                         isInitiator:(BOOL)isInitiator
{
    if ((self = [super init])) {
        self.protocolType = protocolType;
        self.uniqueDeviceID = uniqueDeviceID;
        self.uniqueClientID = uniqueClientID;
        self.isInitiator = isInitiator;
        self.pairingUUID = pairingUUID;
        self.epoch = epoch;
        self.testsEnabled = NO;

        _timeout = 0;
    }
    return self;
}

- (void)encodeWithCoder:(nonnull NSCoder *)coder { 
    [coder encodeObject:_protocolType forKey:@"protocolType"];
    [coder encodeObject:_uniqueClientID forKey:@"uniqueClientID"];
    [coder encodeObject:_uniqueDeviceID forKey:@"uniqueDeviceID"];
    [coder encodeBool:_isInitiator forKey:@"isInitiator"];
    [coder encodeObject:_pairingUUID forKey:@"pairingUUID"];
    [coder encodeInt64:_epoch forKey:@"epoch"];
    [coder encodeInt64:_timeout forKey:@"timeout"];
    [coder encodeBool:_testsEnabled forKey:@"testsEnabled"];
}

- (nullable instancetype)initWithCoder:(nonnull NSCoder *)decoder {
    if ((self = [super init])) {
        _protocolType = [decoder decodeObjectOfClass:[NSString class] forKey:@"protocolType"];
        _uniqueClientID = [decoder decodeObjectOfClass:[NSString class] forKey:@"uniqueClientID"];
        _uniqueDeviceID = [decoder decodeObjectOfClass:[NSString class] forKey:@"uniqueDeviceID"];
        _isInitiator = [decoder decodeBoolForKey:@"isInitiator"];
        _pairingUUID = [decoder decodeObjectOfClass:[NSString class] forKey:@"pairingUUID"];
        _epoch = [decoder decodeInt64ForKey:@"epoch"];
        _timeout = [decoder decodeInt64ForKey:@"timeout"];
        _testsEnabled = [decoder decodeBoolForKey:@"testsEnabled"];
    }
    return self;
}

- (void)enableForTests
{
    self.testsEnabled = YES;
}

@end
NS_ASSUME_NONNULL_END

#endif /* __OBJC2__ */
