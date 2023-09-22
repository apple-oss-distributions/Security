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
#import <objc/runtime.h>
#import <Foundation/NSXPCConnection_Private.h>

#import <utilities/debugging.h>
#import <Security/SecEntitlements.h>
#import "keychain/ot/OctagonControlServer.h"
#import "keychain/ot/OTManager.h"
#import "keychain/ot/OT.h"
#import "keychain/ot/OTConstants.h"
#import "keychain/categories/NSError+UsefulConstructors.h"

#if OCTAGON
@interface OctagonXPCEntitlementChecker ()
@property OTManager* manager;
@property id<OctagonEntitlementBearerProtocol> entitlementBearer;
- (instancetype)initWithManager:(OTManager*)manager
              entitlementBearer:(id<OctagonEntitlementBearerProtocol>)bearer;
@end

@implementation OctagonXPCEntitlementChecker

- (instancetype)initWithManager:(OTManager*)manager entitlementBearer:(id<OctagonEntitlementBearerProtocol>)bearer
{
    // NSProxy does not implement init, so don't call super init
    _manager = manager;
    _entitlementBearer = bearer;
    return self;
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector
{
    return [self.manager methodSignatureForSelector:selector];
}

- (void)forwardInvocation:(NSInvocation *)invocation
{
    if(sel_isEqual(invocation.selector, @selector(fetchEscrowContents:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonEscrow]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonEscrow);
            [invocation setSelector:@selector(failFetchEscrowContents:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    if(sel_isEqual(invocation.selector, @selector(setLocalSecureElementIdentity:secureElementIdentity:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonSecureElement]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonSecureElement);
            [invocation setSelector:@selector(failSetLocalSecureElementIdentity:secureElementIdentity:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    if(sel_isEqual(invocation.selector, @selector(removeLocalSecureElementIdentityPeerID:secureElementIdentityPeerID:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonSecureElement]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonSecureElement);
            [invocation setSelector:@selector(failRemoveLocalSecureElementIdentityPeerID:secureElementIdentityPeerID:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    if(sel_isEqual(invocation.selector, @selector(fetchTrustedSecureElementIdentities:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonSecureElement]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonSecureElement);
            [invocation setSelector:@selector(failFetchTrustedSecureElementIdentities:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    if(sel_isEqual(invocation.selector, @selector(setAccountSetting:setting:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonWalrus]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonWalrus);
            [invocation setSelector:@selector(failSetAccountSetting:setting:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    if(sel_isEqual(invocation.selector, @selector(fetchAccountSettings:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonWalrus]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonWalrus);
            [invocation setSelector:@selector(failFetchAccountSettings:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    if(sel_isEqual(invocation.selector, @selector(fetchAccountWideSettingsWithForceFetch:arguments:reply:))) {
        if(![self.entitlementBearer valueForEntitlement:kSecEntitlementPrivateOctagonWalrus]) {
            secerror("Client %@ does not have entitlement %@, rejecting rpc", self.entitlementBearer, kSecEntitlementPrivateOctagonWalrus);
            [invocation setSelector:@selector(failFetchAccountWideSettingsWithForceFetch:arguments:reply:)];
            [invocation invokeWithTarget:self];
            return;
        }
    }
    [invocation invokeWithTarget:self.manager];
}

- (void)failFetchEscrowContents:(OTConfigurationContext*)arguments
                          reply:(void (^)(NSData* _Nullable entropy,
                                          NSString* _Nullable bottleID,
                                          NSData* _Nullable signingPublicKey,
                                          NSError* _Nullable error))reply
{
    reply(nil, nil, nil, [NSError errorWithDomain:NSOSStatusErrorDomain
                                             code:errSecMissingEntitlement
                                      description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonEscrow]]);
}

- (void)failSetLocalSecureElementIdentity:(OTConfigurationContext*)arguments
                    secureElementIdentity:(OTSecureElementPeerIdentity*)secureElementIdentity
                                    reply:(void (^)(NSError* _Nullable error))reply
{
    reply([NSError errorWithDomain:NSOSStatusErrorDomain
                              code:errSecMissingEntitlement
                       description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonSecureElement]]);
}

- (void)failRemoveLocalSecureElementIdentityPeerID:(OTConfigurationContext*)arguments
                       secureElementIdentityPeerID:(NSData*)sePeerID
                                             reply:(void (^)(NSError* _Nullable error))reply
{
    reply([NSError errorWithDomain:NSOSStatusErrorDomain
                              code:errSecMissingEntitlement
                       description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonSecureElement]]);
}

- (void)failFetchTrustedSecureElementIdentities:(OTConfigurationContext*)arguments
                                          reply:(void (^)(OTCurrentSecureElementIdentities* currentSet,
                                                          NSError* replyError))reply
{
    reply(nil,
          [NSError errorWithDomain:NSOSStatusErrorDomain
                              code:errSecMissingEntitlement
                       description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonSecureElement]]);
}

- (void)failSetAccountSetting:(OTConfigurationContext*)arguments
                      setting:(OTAccountSettings*)setting
                        reply:(void (^)(NSError* _Nullable error))reply
{
    reply([NSError errorWithDomain:NSOSStatusErrorDomain
                              code:errSecMissingEntitlement
                       description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonWalrus]]);
}

- (void)failFetchAccountSettings:(OTConfigurationContext*)arguments
                           reply:(void (^)(OTAccountSettings* setting, NSError* _Nullable error))reply
{
    reply(nil, [NSError errorWithDomain:NSOSStatusErrorDomain
                                   code:errSecMissingEntitlement
                            description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonWalrus]]);
}

- (void)failFetchAccountWideSettingsWithForceFetch:(bool)forceFetch
                                         arguments:(OTConfigurationContext*)arguments
                                             reply:(void (^)(OTAccountSettings* setting, NSError* _Nullable error))reply
{
    reply(nil, [NSError errorWithDomain:NSOSStatusErrorDomain
                                   code:errSecMissingEntitlement
                            description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonWalrus]]);
}

- (void)failPersistAccountSettings:(OTConfigurationContext*)arguments
                           setting:(OTAccountSettings*)setting
                             reply:(void (^)(NSError* _Nullable error))reply
{
    reply([NSError errorWithDomain:NSOSStatusErrorDomain
                              code:errSecMissingEntitlement
                       description:[NSString stringWithFormat: @"Missing entitlement '%@'", kSecEntitlementPrivateOctagonWalrus]]);
}

+ (BOOL)conformsToProtocol:(Protocol *)protocol {
    return [[OTManager class] conformsToProtocol:protocol];
}

// Launder a OctagonXPCEntitlementChecker into something that type-safely implements the protocol we're interested in
+ (id<OTControlProtocol>)createWithManager:(OTManager*)manager
                         entitlementBearer:(id<OctagonEntitlementBearerProtocol>)bearer
{
    return (id<OTControlProtocol>) [[OctagonXPCEntitlementChecker alloc] initWithManager:manager entitlementBearer:bearer];
}
@end
#endif // OCTAGON

@interface OctagonControlServer : NSObject <NSXPCListenerDelegate>
@end

@implementation OctagonControlServer

- (BOOL)listener:(__unused NSXPCListener *)listener shouldAcceptNewConnection:(NSXPCConnection *)newConnection
{
#if OCTAGON
    NSNumber *num = [newConnection valueForEntitlement:kSecEntitlementPrivateOctagon];
    if (![num isKindOfClass:[NSNumber class]] || ![num boolValue]) {
        secerror("octagon: Client pid: %d doesn't have entitlement: %@",
                 [newConnection processIdentifier], kSecEntitlementPrivateOctagon);
        return NO;
    }
    
    secinfo("octagon", "received connection from client pid %d (euid %u)", newConnection.processIdentifier, newConnection.effectiveUserIdentifier);
    newConnection.exportedInterface = OTSetupControlProtocol([NSXPCInterface interfaceWithProtocol:@protocol(OTControlProtocol)]);
    newConnection.exportedObject = [OctagonXPCEntitlementChecker createWithManager:[OTManager manager] entitlementBearer:newConnection];

    [newConnection resume];

    return YES;
#else // OCTAGON
    secerror("octagon does not exist on this platform");
    return NO;
#endif // OCTAGON
}
@end

void
OctagonControlServerInitialize(void)
{
    static dispatch_once_t once;
    static OctagonControlServer *server;
    static NSXPCListener *listener;

    dispatch_once(&once, ^{
        @autoreleasepool {
            server = [OctagonControlServer new];

            listener = [[NSXPCListener alloc] initWithMachServiceName:@(kSecuritydOctagonServiceName)];
            listener.delegate = server;
            [listener resume];
        }
    });
}
