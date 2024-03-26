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

#import "keychain/ot/OTResetOperation.h"

#import <Security/SecInternalReleasePriv.h>
#import "keychain/categories/NSError+UsefulConstructors.h"
#import "keychain/ot/ObjCImprovements.h"
#import "keychain/TrustedPeersHelper/TrustedPeersHelperProtocol.h"

@interface OTResetOperation ()
@property NSString* containerName;
@property NSString* contextID;
@property CuttlefishXPCWrapper* cuttlefishXPCWrapper;
@property OTOperationDependencies* deps;

// Since we're making callback based async calls, use this operation trick to hold off the ending of this operation
@property NSOperation* finishedOp;
@end

@implementation OTResetOperation
@synthesize intendedState = _intendedState;
@synthesize nextState = _nextState;

- (instancetype)init:(NSString*)containerName
           contextID:(NSString*)contextID
              reason:(CuttlefishResetReason)reason
   idmsTargetContext:(NSString *_Nullable)idmsTargetContext
idmsCuttlefishPassword:(NSString *_Nullable)idmsCuttlefishPassword
          notifyIdMS:(bool)notifyIdMS
       intendedState:(OctagonState*)intendedState
        dependencies:(OTOperationDependencies *)deps
          errorState:(OctagonState*)errorState
cuttlefishXPCWrapper:(CuttlefishXPCWrapper*)cuttlefishXPCWrapper
{
    if((self = [super init])) {
        _intendedState = intendedState;
        _nextState = errorState;

        _containerName = containerName;
        _contextID = contextID;
        _cuttlefishXPCWrapper = cuttlefishXPCWrapper;
        _resetReason = reason;
        _idmsTargetContext = idmsTargetContext;
        _idmsCuttlefishPassword = idmsCuttlefishPassword;
        _notifyIdMS = notifyIdMS;
        _deps = deps;
    }
    return self;
}

- (void)groupStart
{
    secnotice("octagon-authkit", "Attempting to reset octagon");

    self.finishedOp = [[NSOperation alloc] init];
    [self dependOnBeforeGroupFinished:self.finishedOp];

    NSString* altDSID = self.deps.activeAccount.altDSID;
    if(altDSID == nil) {
        secnotice("authkit", "No configured altDSID: %@", self.deps.activeAccount);
        self.error = [NSError errorWithDomain:OctagonErrorDomain
                                         code:OctagonErrorNoAppleAccount
                                  description:@"No altDSID configured"];
        [self runBeforeGroupFinished:self.finishedOp];
        return;
    }

    NSError* localError = nil;
    BOOL isAccountDemo = [self.deps.authKitAdapter accountIsDemoAccountByAltDSID:altDSID error:&localError];
    if(localError) {
        secerror("octagon-authkit: failed to fetch demo account flag: %@", localError);
    }

    BOOL internal = SecIsInternalRelease();

    WEAKIFY(self);
    [self.cuttlefishXPCWrapper resetWithSpecificUser:self.deps.activeAccount
                                         resetReason:self.resetReason
                                   idmsTargetContext:self.idmsTargetContext
                              idmsCuttlefishPassword:self.idmsCuttlefishPassword
                                          notifyIdMS:self.notifyIdMS
                                     internalAccount:internal
                                         demoAccount:isAccountDemo
                                               reply:^(NSError * _Nullable error) {
            STRONGIFY(self);
            [[CKKSAnalytics logger] logResultForEvent:OctagonEventReset hardFailure:true result:error];
        
            if(error) {
                secnotice("octagon", "Unable to reset for (%@,%@): %@", self.containerName, self.contextID, error);
                self.error = error;
            } else {

                secnotice("octagon", "Successfully reset Octagon");
                NSError* localError = nil;
                [self.deps.stateHolder persistAccountChanges:^OTAccountMetadataClassC * _Nonnull(OTAccountMetadataClassC * _Nonnull metadata) {
                    metadata.trustState = OTAccountMetadataClassC_TrustState_UNKNOWN;
                    metadata.peerID = nil;
                    metadata.syncingPolicy = nil;

                    // Don't touch the CDP or account states; those can carry over

                    metadata.voucher = nil;
                    metadata.voucherSignature = nil;
                    metadata.tlkSharesForVouchedIdentitys = nil;
                    metadata.isInheritedAccount = NO;
                    metadata.warmedEscrowCache = NO;
                    metadata.warnedTooManyPeers = NO;

                    return metadata;
                } error:&localError];

                if(localError) {
                    secnotice("octagon", "Error resetting local account metadata state: %@", localError);
                } else {
                    secnotice("octagon", "Successfully reset local account metadata state");
                }
                
                self.nextState = self.intendedState;
            }

            [self runBeforeGroupFinished:self.finishedOp];
        }];
}

@end

#endif // OCTAGON
