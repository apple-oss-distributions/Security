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

#ifndef SECURITY_OT_OTCONTROLPROTOCOL_H
#define SECURITY_OT_OTCONTROLPROTOCOL_H 1

#ifdef __OBJC__

#import <Foundation/Foundation.h>

#import <AppleFeatures/AppleFeatures.h>

#import <Security/OTClique.h>
#import <Security/OTConstants.h>
@class SFECKeyPair;
@class OTSecureElementPeerIdentity;
@class OTCurrentSecureElementIdentities;

NS_ASSUME_NONNULL_BEGIN

@class OTJoiningConfiguration;

@protocol OTControlProtocol
- (void)restore:(NSString *)contextID dsid:(NSString *)dsid secret:(NSData*)secret escrowRecordID:(NSString*)escrowRecordID reply:(void (^)(NSData* _Nullable signingKeyData, NSData* _Nullable encryptionKeyData, NSError * _Nullable error))reply;
- (void)octagonEncryptionPublicKey:(void (^)(NSData* _Nullable encryptionKey, NSError * _Nullable))reply;
- (void)octagonSigningPublicKey:(void (^)(NSData* _Nullable signingKey, NSError * _Nullable))reply;
- (void)listOfEligibleBottledPeerRecords:(void (^)(NSArray* _Nullable listOfRecords, NSError * _Nullable))reply;

// If you're not sure about container, pass nil. If you're not sure about context, pass OTDefaultContext.
- (void)signIn:(NSString*)altDSID
     container:(NSString* _Nullable)container
       context:(NSString*)contextID
         reply:(void (^)(NSError * _Nullable error))reply;

- (void)signOut:(NSString* _Nullable)container
        context:(NSString*)contextID
          reply:(void (^)(NSError * _Nullable error))reply;

- (void)notifyIDMSTrustLevelChangeForContainer:(NSString* _Nullable)container
                                       context:(NSString*)contextID
                                         reply:(void (^)(NSError * _Nullable error))reply;

- (void)reset:(void (^)(BOOL result, NSError * _Nullable error))reply;

- (void)handleIdentityChangeForSigningKey:(SFECKeyPair*)peerSigningKey
                         ForEncryptionKey:(SFECKeyPair*)encryptionKey
                                ForPeerID:(NSString*)peerID
                                    reply:(void (^)(BOOL result,
                                                    NSError* _Nullable error))reply;

- (void)rpcEpochWithConfiguration:(OTJoiningConfiguration*)config
                            reply:(void (^)(uint64_t epoch,
                                            NSError * _Nullable error))reply;

- (void)rpcPrepareIdentityAsApplicantWithConfiguration:(OTJoiningConfiguration*)config
                                              reply:(void (^)(NSString * _Nullable peerID,
                                                              NSData * _Nullable permanentInfo,
                                                              NSData * _Nullable permanentInfoSig,
                                                              NSData * _Nullable stableInfo,
                                                              NSData * _Nullable stableInfoSig,
                                                              NSError * _Nullable error))reply;
- (void)rpcVoucherWithConfiguration:(OTJoiningConfiguration*)config
                             peerID:(NSString*)peerID
                      permanentInfo:(NSData *)permanentInfo
                   permanentInfoSig:(NSData *)permanentInfoSig
                         stableInfo:(NSData *)stableInfo
                      stableInfoSig:(NSData *)stableInfoSig
                              reply:(void (^)(NSData* voucher, NSData* voucherSig, NSError * _Nullable error))reply;

- (void)rpcJoinWithConfiguration:(OTJoiningConfiguration*)config
                       vouchData:(NSData*)vouchData
                        vouchSig:(NSData*)vouchSig
                           reply:(void (^)(NSError * _Nullable error))reply;

- (void)preflightBottledPeer:(NSString*)contextID
                        dsid:(NSString*)dsid
                       reply:(void (^)(NSData* _Nullable entropy,
                                       NSString* _Nullable bottleID,
                                       NSData* _Nullable signingPublicKey,
                                       NSError* _Nullable error))reply;
- (void)launchBottledPeer:(NSString*)contextID
                 bottleID:(NSString*)bottleID
                    reply:(void (^ _Nullable)(NSError* _Nullable error))reply;
- (void)scrubBottledPeer:(NSString*)contextID
                bottleID:(NSString*)bottleID
                   reply:(void (^ _Nullable)(NSError* _Nullable error))reply;

- (void)status:(NSString* _Nullable)container
       context:(NSString*)context
         reply:(void (^)(NSDictionary* _Nullable result, NSError* _Nullable error))reply;

- (void)fetchEgoPeerID:(NSString* _Nullable)container
               context:(NSString*)context
                 reply:(void (^)(NSString* _Nullable peerID, NSError* _Nullable error))reply;

- (void)fetchCliqueStatus:(NSString* _Nullable)container
                  context:(NSString*)context
            configuration:(OTOperationConfiguration*)configuration
                    reply:(void (^)(CliqueStatus cliqueStatus, NSError* _Nullable error))reply;

- (void)fetchTrustStatus:(NSString* _Nullable)container
                 context:(NSString*)context
           configuration:(OTOperationConfiguration *)configuration
                   reply:(void (^)(CliqueStatus status,
                                   NSString* _Nullable peerID,
                                   NSNumber* _Nullable numberOfPeersInOctagon,
                                   BOOL isExcluded,
                                   NSError* _Nullable error))reply;

// Likely won't be used once Octagon is turned on for good
- (void)startOctagonStateMachine:(NSString* _Nullable)container
                         context:(NSString*)context
                           reply:(void (^)(NSError* _Nullable error))reply;

- (void)resetAndEstablish:(NSString* _Nullable)container
                  context:(NSString*)context
                  altDSID:(NSString*)altDSID
              resetReason:(CuttlefishResetReason)resetReason
                    reply:(void (^)(NSError* _Nullable error))reply;

- (void)establish:(NSString * _Nullable)container
                 context:(NSString *)context
                 altDSID:(NSString*)altDSID
                   reply:(void (^)(NSError * _Nullable))reply;

- (void)leaveClique:(NSString* _Nullable)container
            context:(NSString*)context
              reply:(void (^)(NSError* _Nullable error))reply;

- (void)removeFriendsInClique:(NSString* _Nullable)container
                      context:(NSString*)context
                      peerIDs:(NSArray<NSString*>*)peerIDs
                        reply:(void (^)(NSError* _Nullable error))reply;

- (void)peerDeviceNamesByPeerID:(NSString* _Nullable)container
                        context:(NSString*)context
                          reply:(void (^)(NSDictionary<NSString*, NSString*>* _Nullable peers, NSError* _Nullable error))reply;

- (void)fetchAllViableBottles:(NSString* _Nullable)container
                      context:(NSString*)context
                        reply:(void (^)(NSArray<NSString*>* _Nullable sortedBottleIDs, NSArray<NSString*> * _Nullable sortedPartialBottleIDs, NSError* _Nullable error))reply;

-(void)restore:(NSString* _Nullable)containerName
     contextID:(NSString *)contextID
    bottleSalt:(NSString *)bottleSalt
       entropy:(NSData *)entropy
      bottleID:(NSString *)bottleID
         reply:(void (^)(NSError * _Nullable))reply;

- (void)fetchEscrowContents:(NSString* _Nullable)containerName
                  contextID:(NSString *)contextID
                      reply:(void (^)(NSData* _Nullable entropy,
                                      NSString* _Nullable bottleID,
                                      NSData* _Nullable signingPublicKey,
                                      NSError* _Nullable error))reply;

- (void) createRecoveryKey:(NSString* _Nullable)containerName
                 contextID:(NSString *)contextID
               recoveryKey:(NSString *)recoveryKey
                     reply:(void (^)( NSError * _Nullable))reply;

- (void) joinWithRecoveryKey:(NSString* _Nullable)containerName
                   contextID:(NSString *)contextID
                 recoveryKey:(NSString*)recoveryKey
                       reply:(void (^)(NSError * _Nullable))reply;

- (void) createCustodianRecoveryKey:(NSString* _Nullable)containerName
                          contextID:(NSString *)contextID
                               uuid:(NSUUID *_Nullable)uuid
                              reply:(void (^)(OTCustodianRecoveryKey *_Nullable crk, NSError *_Nullable error))reply;

- (void) joinWithCustodianRecoveryKey:(NSString* _Nullable)containerName
                            contextID:(NSString *)contextID
                 custodianRecoveryKey:(OTCustodianRecoveryKey *)crk
                                reply:(void(^)(NSError* _Nullable error)) reply;

- (void) preflightJoinWithCustodianRecoveryKey:(NSString* _Nullable)containerName
                                     contextID:(NSString *)contextID
                          custodianRecoveryKey:(OTCustodianRecoveryKey *)crk
                                         reply:(void(^)(NSError* _Nullable error)) reply;

- (void) removeCustodianRecoveryKey:(NSString* _Nullable)containerName
                          contextID:(NSString *)contextID
                               uuid:(NSUUID *)uuid
                              reply:(void (^)(NSError *_Nullable error))reply;

- (void) createInheritanceKey:(NSString* _Nullable)containerName
                    contextID:(NSString *)contextID
                         uuid:(NSUUID *_Nullable)uuid
                        reply:(void (^)(OTInheritanceKey *_Nullable ik, NSError *_Nullable error))reply;

- (void) generateInheritanceKey:(NSString* _Nullable)containerName
                    contextID:(NSString *)contextID
                         uuid:(NSUUID *_Nullable)uuid
                        reply:(void (^)(OTInheritanceKey *_Nullable ik, NSError *_Nullable error))reply;

- (void) storeInheritanceKey:(NSString* _Nullable)containerName
                   contextID:(NSString *)contextID
                          ik:(OTInheritanceKey *)ik
                       reply:(void (^)(NSError *_Nullable error)) reply;

- (void) joinWithInheritanceKey:(NSString* _Nullable)containerName
                      contextID:(NSString *)contextID
                 inheritanceKey:(OTInheritanceKey *)crk
                          reply:(void(^)(NSError* _Nullable error)) reply;

- (void) preflightJoinWithInheritanceKey:(NSString* _Nullable)containerName
                               contextID:(NSString *)contextID
                          inheritanceKey:(OTInheritanceKey *)crk
                                   reply:(void(^)(NSError* _Nullable error)) reply;

- (void) removeInheritanceKey:(NSString* _Nullable)containerName
                    contextID:(NSString *)contextID
                         uuid:(NSUUID *)uuid
                        reply:(void (^)(NSError *_Nullable error))reply;

- (void)healthCheck:(NSString * _Nullable)container
            context:(NSString *)context
skipRateLimitingCheck:(BOOL)skipRateLimitingCheck
              reply:(void (^)(NSError *_Nullable error))reply;

- (void)waitForOctagonUpgrade:(NSString* _Nullable)container
                      context:(NSString*)context
                        reply:(void (^)(NSError* _Nullable error))reply;

- (void)postCDPFollowupResult:(BOOL)success
                         type:(OTCliqueCDPContextType)type
                        error:(NSError * _Nullable)error
                containerName:(NSString* _Nullable)containerName
                  contextName:(NSString *)contextName
                        reply:(void (^)(NSError* _Nullable error))reply;

- (void)tapToRadar:(NSString *)action
       description:(NSString *)description
             radar:(NSString *)radar
             reply:(void (^)(NSError* _Nullable error))reply;

- (void)refetchCKKSPolicy:(NSString* _Nullable)container
                contextID:(NSString*)contextID
                    reply:(void (^)(NSError* _Nullable error))reply;

- (void)setCDPEnabled:(NSString* _Nullable)containerName
            contextID:(NSString*)contextID
                reply:(void (^)(NSError* _Nullable error))reply;

- (void)getCDPStatus:(NSString* _Nullable)containerName
           contextID:(NSString*)contextID
               reply:(void (^)(OTCDPStatus status, NSError* _Nullable error))reply;

- (void)fetchEscrowRecords:(NSString * _Nullable)container
                 contextID:(NSString*)contextID
                forceFetch:(BOOL)forceFetch
                     reply:(void (^)(NSArray<NSData*>* _Nullable records,
                                     NSError* _Nullable error))reply;

- (void)invalidateEscrowCache:(NSString * _Nullable)containerName
                    contextID:(NSString*)contextID
                        reply:(nonnull void (^)(NSError * _Nullable error))reply;

/* View Handling */
- (void)setUserControllableViewsSyncStatus:(NSString* _Nullable)containerName
                                 contextID:(NSString*)contextID
                                   enabled:(BOOL)enabled
                                     reply:(void (^)(BOOL nowSyncing, NSError* _Nullable error))reply;

- (void)fetchUserControllableViewsSyncStatus:(NSString* _Nullable)containerName
                                   contextID:(NSString*)contextID
                                       reply:(void (^)(BOOL nowSyncing, NSError* _Nullable error))reply;

- (void)resetAccountCDPContents:(NSString* _Nullable)containerName
                      contextID:(NSString*)contextID
                          reply:(void (^)(NSError* _Nullable error))reply;

- (void)setLocalSecureElementIdentity:(NSString* _Nullable)containerName
                            contextID:(NSString*)contextID
                secureElementIdentity:(OTSecureElementPeerIdentity*)secureElementIdentity
                                reply:(void (^)(NSError* _Nullable))reply;

- (void)removeLocalSecureElementIdentityPeerID:(NSString* _Nullable)containerName
                                     contextID:(NSString*)contextID
                   secureElementIdentityPeerID:(NSData*)sePeerID
                                         reply:(void (^)(NSError* _Nullable))reply;

- (void)fetchTrustedSecureElementIdentities:(NSString* _Nullable)containerName
                                  contextID:(NSString*)contextID
                                      reply:(void (^)(OTCurrentSecureElementIdentities* _Nullable currentSet,
                                                      NSError* _Nullable replyError))reply;


- (void)waitForPriorityViewKeychainDataRecovery:(NSString* _Nullable)containerName
                                      contextID:(NSString*)contextID
                                          reply:(void (^)(NSError* _Nullable replyError))reply;

- (void)tlkRecoverabilityForEscrowRecordData:(NSString* _Nullable)containerName
                                   contextID:(NSString*)contextID
                                  recordData:(NSData*)recordData
                                       reply:(void (^)(NSArray<NSString*>* _Nullable views, NSError* _Nullable error))reply;
@end

NSXPCInterface* OTSetupControlProtocol(NSXPCInterface* interface);

NS_ASSUME_NONNULL_END

#endif /* __OBJC__ */

#endif /* SECURITY_OT_OTCONTROLPROTOCOL_H */
