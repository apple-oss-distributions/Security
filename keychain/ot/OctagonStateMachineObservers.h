
#if OCTAGON

#import <Foundation/Foundation.h>
#import "keychain/ckks/CKKSResultOperation.h"
#import "keychain/ckks/CKKSAnalytics.h"
#import "keychain/ot/OctagonStateMachineHelpers.h"

NS_ASSUME_NONNULL_BEGIN

@class OctagonStateMachine;

@interface OctagonStateTransitionPathStep : NSObject
@property BOOL successState;
@property (readonly) NSDictionary<OctagonState*, OctagonStateTransitionPathStep*>* followStates;

- (instancetype)initAsSuccess;
- (instancetype)initWithPath:(NSDictionary<OctagonState*, OctagonStateTransitionPathStep*>*)followStates;

- (BOOL)successState;

+ (OctagonStateTransitionPathStep*)success;

// Dict should be a map of states to either:
//  1. A dictionary matching this specifiction
//  2. an OctagonStateTransitionPathStep object (which is likely a success object, but doesn't have to be)
// Any other object will be ignored. A malformed dictionary will be converted into an empty success path.
+ (OctagonStateTransitionPathStep*)pathFromDictionary:(NSDictionary<OctagonState*, id>*)pathDict;
@end


@interface OctagonStateTransitionPath : NSObject
@property OctagonState* initialState;
@property OctagonStateTransitionPathStep* pathStep;

- (instancetype)initWithState:(OctagonState*)initialState
                     pathStep:(OctagonStateTransitionPathStep*)pathSteps;

- (OctagonStateTransitionPathStep*)asPathStep;

// Uses the same rules as OctagonStateTransitionPathStep pathFromDictionary, but selects one of the top-level dictionary keys
// to be the path initialization state. Not well defined if you pass in two keys in the top-level dictionary.
// If the dictionary has no keys in it, returns nil.
+ (OctagonStateTransitionPath* _Nullable)pathFromDictionary:(NSDictionary<OctagonState*, id>*)pathDict;

@end



@protocol OctagonStateTransitionWatcherProtocol
@property (readonly) CKKSResultOperation* result;
- (void)onqueueHandleTransition:(CKKSResultOperation<OctagonStateTransitionOperationProtocol>*)attempt;
- (void)onqueueHandleStartTimeout:(NSError*)stateMachineStateError;
@end

@interface OctagonStateTransitionWatcher : NSObject <OctagonStateTransitionWatcherProtocol>
@property (readonly) NSString* name;
@property (readonly) CKKSResultOperation* result;
@property (readonly) OctagonStateTransitionPath* intendedPath;

// If the initial request times out, the watcher will fail as well.
- (instancetype)initNamed:(NSString*)name
             stateMachine:(OctagonStateMachine*)stateMachine
                     path:(OctagonStateTransitionPath*)path
           initialRequest:(OctagonStateTransitionRequest* _Nullable)initialRequest;
@end

// Reports on if any of the given states are entered
@interface OctagonStateMultiStateArrivalWatcher : NSObject <OctagonStateTransitionWatcherProtocol>
@property (readonly) NSString* name;
@property (readonly) CKKSResultOperation* result;
@property (readonly) NSSet<OctagonState*>* states;
@property (readonly) NSDictionary<OctagonState*, NSError*>* failStates;

- (instancetype)initNamed:(NSString*)name
              serialQueue:(dispatch_queue_t)queue
                   states:(NSSet<OctagonState*>*)states;

- (instancetype)initNamed:(NSString*)name
              serialQueue:(dispatch_queue_t)queue
                   states:(NSSet<OctagonState*>*)states
               failStates:(NSDictionary<OctagonState*, NSError*>*)failStates;

// Called by the state machine if it's already in a state at registration time
- (void)onqueueEnterState:(OctagonState*)state;

// If the watcher is still waiting to complete or timeout, cause it to finish with this error
- (void)completeWithErrorIfPending:(NSError*)error;
@end

NS_ASSUME_NONNULL_END

#endif // OCTAGON
