
#import <Foundation/Foundation.h>
#if OCTAGON

#import "keychain/ot/OTSOSAdapter.h"
#include "keychain/SecureObjectSync/SOSAccount.h"

NS_ASSUME_NONNULL_BEGIN

@interface CKKSMockSOSPresentAdapter : NSObject <OTSOSAdapter>

// If you fill these in, the OTSOSAdapter methods will error with these errors.
@property (nullable) NSError* selfPeerError;
@property (nullable) NSError* trustedPeersError;

@property BOOL aksLocked;

@property bool excludeSelfPeerFromTrustSet;

@property SOSCCStatus circleStatus;
@property (nullable) NSError* circleStatusError;

@property CKKSSOSSelfPeer* selfPeer;
@property NSMutableSet<id<CKKSSOSPeerProtocol>>* trustedPeers;

@property BOOL safariViewEnabled;

@property BOOL ckks4AllStatus;
@property BOOL ckks4AllStatusIsSet;

@property bool joinAfterRestoreCircleStatusOverride;
@property bool joinAfterRestoreResult;

@property bool resetToOfferingCircleStatusOverride;
@property bool resetToOfferingResult;

@property (nullable) void (^updateOctagonKeySetListener)(id<CKKSSelfPeer>);

- (instancetype)initWithSelfPeer:(CKKSSOSSelfPeer*)selfPeer
                    trustedPeers:(NSSet<id<CKKSSOSPeerProtocol>>*)trustedPeers
                       essential:(BOOL)essential;

- (NSSet<id<CKKSRemotePeerProtocol>>*)allPeers;

- (void)setSOSEnabled:(bool)isEnabled;

@end

NS_ASSUME_NONNULL_END

#endif // OCTAGON
