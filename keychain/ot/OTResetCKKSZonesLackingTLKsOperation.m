#if OCTAGON

#import "utilities/debugging.h"

#import <CloudKit/CloudKit_Private.h>

#import "keychain/ot/OTResetCKKSZonesLackingTLKsOperation.h"
#import "keychain/ot/OTCuttlefishAccountStateHolder.h"
#import "keychain/ot/OTFetchCKKSKeysOperation.h"

#import "keychain/ckks/CloudKitCategories.h"
#import "keychain/ckks/CKKSCurrentKeyPointer.h"
#import "keychain/ckks/CKKSKeychainView.h"

#import "keychain/ot/ObjCImprovements.h"
#import <KeychainCircle/AAFAnalyticsEvent+Security.h>
#import <KeychainCircle/SecurityAnalyticsConstants.h>

@interface OTResetCKKSZonesLackingTLKsOperation ()
@property OTOperationDependencies* deps;

@property NSOperation* finishedOp;
@end

@implementation OTResetCKKSZonesLackingTLKsOperation
@synthesize nextState = _nextState;
@synthesize intendedState = _intendedState;

- (instancetype)initWithDependencies:(OTOperationDependencies*)dependencies
                       intendedState:(OctagonState*)intendedState
                          errorState:(OctagonState*)errorState
{
    if((self = [super init])) {
        _deps = dependencies;

        _intendedState = intendedState;
        _nextState = errorState;
    }
    return self;
}

- (void)groupStart
{
    secnotice("octagon", "Checking if any CKKS zones need resetting");

    NSDictionary* metrics = nil;
    metrics = @{kSecurityRTCFieldAccountIsW : @(self.deps.accountIsW)};
    AAFAnalyticsEventSecurity* event = [[AAFAnalyticsEventSecurity alloc] initWithKeychainCircleMetrics:metrics
                                                                                                altDSID:self.deps.activeAccount.altDSID
                                                                                                 flowID:self.deps.flowID
                                                                                        deviceSessionID:self.deps.deviceSessionID
                                                                                              eventName:kSecurityRTCEventNameResetCKKSZonesLackingTLKsOperation
                                                                                        testsAreEnabled:SecCKKSTestsEnabled()
                                                                                         canSendMetrics:self.deps.permittedToSendMetrics
                                                                                               category:kSecurityRTCEventCategoryAccountDataAccessRecovery];
    WEAKIFY(self);

    self.finishedOp = [NSBlockOperation blockOperationWithBlock:^{
        STRONGIFY(self);
        secnotice("octagon", "Finishing resetting CKKS missing TLKs operation with %@", self.error ?: @"no error");
        if (self.error) {
            [event sendMetricWithResult:NO error:self.error];
        } else {
            [event sendMetricWithResult:YES error:nil];
        }
    }];
    [self dependOnBeforeGroupFinished:self.finishedOp];

    OTFetchCKKSKeysOperation* fetchKeysOp = [[OTFetchCKKSKeysOperation alloc] initWithDependencies:self.deps
                                                                                     refetchNeeded:NO];
    [self runBeforeGroupFinished:fetchKeysOp];

    CKKSResultOperation* proceedWithKeys = [CKKSResultOperation named:@"continue-ckks-resets"
                                                            withBlock:^{
                                                                STRONGIFY(self);
                                                                [self proceedWithKeys:fetchKeysOp.viewKeySets
                                                                    incompleteKeySets:fetchKeysOp.incompleteKeySets];
                                                            }];

    [proceedWithKeys addDependency:fetchKeysOp];
    [self runBeforeGroupFinished:proceedWithKeys];
}

- (void)proceedWithKeys:(NSArray<CKKSKeychainBackedKeySet*>*)viewKeySets
      incompleteKeySets:(NSArray<CKKSCurrentKeySet*>*)incompleteKeySets
{
    // Now that CKKS has returned, what are we even doing
    NSMutableSet<NSString*>* viewsToReset = [NSMutableSet set];

    for(CKKSCurrentKeySet* incompleteKeySet in incompleteKeySets) {
        if(incompleteKeySet.error == nil) {

            if(incompleteKeySet.currentTLKPointer != nil &&
               incompleteKeySet.tlk == nil) {

                // We used to not reset the TLKs if there was a recent device claiming to have them, but
                // in our Octagon-primary world, an Octagon reset should take precedence over existing Cloud-based data
                secnotice("octagon-ckks", "Key set %@ has no TLK; scheduling for reset", incompleteKeySet);
                [viewsToReset addObject:incompleteKeySet.zoneID.zoneName];
            }
        } else {
            secnotice("octagon-ckks", "Error loading key set %@; not attempting reset", incompleteKeySet);
        }
    }

    if(viewsToReset.count == 0) {
        // Nothing to do; return to ready
        secnotice("octagon-ckks", "No CKKS views need resetting");
        self.nextState = self.intendedState;
        [self runBeforeGroupFinished:self.finishedOp];
        return;
    }

    [self resetViews:viewsToReset];
}

- (void)resetViews:(NSSet<NSString*>*)viewsToReset {
    secnotice("octagon-ckks", "Resetting CKKS view %@", viewsToReset);

    CKKSResultOperation* op = [self.deps.ckks rpcResetCloudKit:viewsToReset
                                                         reply:^(NSError * _Nullable result) {
        secnotice("octagon-ckks", "CKKS view reset complete");
    }];

    // Use an intermediary operation, just to ensure we have a timeout
    CKKSResultOperation* waitOp = [CKKSResultOperation named:@"wait-for-ckks-reset"
                                                   withBlock:^{
        secnotice("octagon-ckks", "Successfully reset %@", viewsToReset);
    }];
    [waitOp timeout:120*NSEC_PER_SEC];
    [waitOp addDependency:op];

    [self.operationQueue addOperation:waitOp];
    [self.finishedOp addDependency:waitOp];

    self.nextState = self.intendedState;
    [self.operationQueue addOperation:self.finishedOp];
}

@end

#endif // OCTAGON
