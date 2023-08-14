
#if OCTAGON

#import <Foundation/Foundation.h>
#import <CloudKit/CloudKit.h>

#import <Security/SecLaunchSequence.h>
#import "keychain/ckks/CKKS.h"
#import "keychain/ckks/CKKSStates.h"
#import "keychain/ckks/CKKSNearFutureScheduler.h"
#import "keychain/ot/OctagonStateMachine.h"

NS_ASSUME_NONNULL_BEGIN
@class OctagonStateMachine;

@interface CKKSKeychainViewState : NSObject <NSCopying>
@property (readonly) NSString* zoneName;
@property (readonly) CKRecordZoneID* zoneID;
@property (readonly) NSString* contextID;

@property (nullable) SecLaunchSequence* launch;

// Intended to track the current idea of the key hierarchy for a given zone.
@property CKKSZoneKeyState* viewKeyHierarchyState;
@property (readonly) NSDictionary<CKKSZoneKeyState*, CKKSCondition*>* keyHierarchyConditions;

// This is YES if CKKS should be managing this view: establishing a key hierarchy, processing incoming queue entries, etc.
@property (readonly) BOOL ckksManagedView;

// This is YES if the initial download of this view should be prioritized over other views.
@property (readonly) BOOL priorityView;

/* Trigger this to tell the whole machine that this view has changed */
@property CKKSNearFutureScheduler* notifyViewChangedScheduler;

/* Trigger this to tell the whole machine that this view is more ready then before */
@property CKKSNearFutureScheduler* notifyViewReadyScheduler;

- (instancetype)initWithZoneID:(CKRecordZoneID*)zoneID
                  forContextID:(NSString *)contextID
               ckksManagedView:(BOOL)ckksManagedView
                  priorityView:(BOOL)priorityView
    notifyViewChangedScheduler:(CKKSNearFutureScheduler*)notifyViewChangedScheduler
      notifyViewReadyScheduler:(CKKSNearFutureScheduler*)notifyViewReadyScheduler;

- (void)launchComplete;

// Unless this is called, calling launchComplete will not trigger the notifyViewReadyScheduler.
- (void)armReadyNotification;
@end

NS_ASSUME_NONNULL_END

#endif
