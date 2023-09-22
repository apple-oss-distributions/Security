
#import <Foundation/Foundation.h>

#if OCTAGON

#import "keychain/ckks/CKKSGroupOperation.h"
#import "keychain/ot/OctagonStateMachineHelpers.h"
#import "keychain/ot/OTOperationDependencies.h"

NS_ASSUME_NONNULL_BEGIN

@interface OTDetermineCDPCapableAccountStatusOperation : CKKSGroupOperation <OctagonStateTransitionOperationProtocol>
- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithDependencies:(OTOperationDependencies*)dependencies
                   stateIfCDPCapable:(OctagonState*)stateIfCDPCapable
                stateIfNotCDPCapable:(OctagonState*)stateIfNotCDPCapable
                    stateIfNoAccount:(OctagonState*)stateIfNoAccount
                          errorState:(OctagonState*)errorState;

@property OctagonState* nextState;
@end

NS_ASSUME_NONNULL_END

#endif // OCTAGON
