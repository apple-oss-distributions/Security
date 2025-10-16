
#if OCTAGON

#import <Foundation/Foundation.h>
#import "keychain/ckks/CKKSGroupOperation.h"
#import "keychain/ot/OctagonStateMachineHelpers.h"

#import "keychain/ot/OTAuthKitAdapter.h"
#import "keychain/ot/OTDeviceInformation.h"

NS_ASSUME_NONNULL_BEGIN

@class OTOperationDependencies;

@interface OTUpdateTPHOperation : CKKSGroupOperation <OctagonStateTransitionOperationProtocol>

- (instancetype)initWithDependencies:(OTOperationDependencies*)dependencies
                          deviceInfo:(OTDeviceInformation*)deviceInfo
                       intendedState:(OctagonState*)intendedState
                    peerUnknownState:(OctagonState* _Nullable)peerUnknownState
                   determineCDPState:(OctagonState* _Nullable)determineCDPState
                          errorState:(OctagonState*)errorState
                        forceRefetch:(BOOL)forceRefetch
                           retryFlag:(OctagonFlag* _Nullable)retryFlag;
@end

NS_ASSUME_NONNULL_END

#endif
