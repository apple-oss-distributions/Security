#if OCTAGON

#import "keychain/categories/NSError+UsefulConstructors.h"
#import "keychain/ot/ObjCImprovements.h"
#import "keychain/ot/OctagonStateMachine.h"
#import "keychain/ot/OctagonStateMachineObservers.h"
#import "keychain/ot/OTDefines.h"
#import "keychain/ot/OTConstants.h"

@implementation OctagonStateTransitionPathStep

- (instancetype)initAsSuccess
{
    if((self = [super init])) {
        _successState = YES;
        _followStates = @{};
    }
    return self;
}
- (instancetype)initWithPath:(NSDictionary<OctagonState*, OctagonStateTransitionPathStep*>*)followStates
{
    if((self = [super init])) {
        _successState = NO;
        _followStates = followStates;
    }
    return self;
}

- (OctagonStateTransitionPathStep*)nextStep:(OctagonState*)stateStep
{
    // If stateStep matches a followState, return it. Otherwise, return nil.
    return self.followStates[stateStep];
}

- (NSString*)description
{
    return [NSString stringWithFormat:@"<OSTPath(%@)>", self.followStates.allKeys];
}

+ (OctagonStateTransitionPathStep*)success
{
    return [[OctagonStateTransitionPathStep alloc] initAsSuccess];
}

+ (OctagonStateTransitionPathStep*)pathFromDictionary:(NSDictionary<OctagonState*, id>*)pathDict
{
    NSMutableDictionary<OctagonState*, OctagonStateTransitionPathStep*>* converted = [NSMutableDictionary dictionary];
    for(id key in pathDict.allKeys) {
        id obj = pathDict[key];

        if([obj isKindOfClass:[OctagonStateTransitionPathStep class]]) {
            converted[key] = obj;
        } else if([obj isKindOfClass:[NSDictionary class]]) {
            converted[key] = [OctagonStateTransitionPathStep pathFromDictionary:(NSDictionary*)obj];
        }
    }

    if([converted count] == 0) {
        return [[OctagonStateTransitionPathStep alloc] initAsSuccess];
    }

    return [[OctagonStateTransitionPathStep alloc] initWithPath:converted];
}
@end

#pragma mark - OctagonStateTransitionPath

@implementation OctagonStateTransitionPath
- (instancetype)initWithState:(OctagonState*)initialState
                     pathStep:(OctagonStateTransitionPathStep*)pathStep
{
    if((self = [super init])) {
        _initialState = initialState;
        _pathStep = pathStep;
    }
    return self;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<OctagonStateTransitionPath: %@ %@", self.initialState, self.pathStep];
}

- (OctagonStateTransitionPathStep*)asPathStep
{
    return [[OctagonStateTransitionPathStep alloc] initWithPath:@{
        self.initialState: self.pathStep,
    }];
}

+ (OctagonStateTransitionPath* _Nullable)pathFromDictionary:(NSDictionary<OctagonState*, id>*)pathDict
{
    for(id key in pathDict.allKeys) {
        id obj = pathDict[key];

        if([obj isKindOfClass:[OctagonStateTransitionPathStep class]]) {
            return [[OctagonStateTransitionPath alloc] initWithState:key
                                                            pathStep:obj];
        } else if([obj isKindOfClass:[NSDictionary class]]) {
            return [[OctagonStateTransitionPath alloc] initWithState:key
                                                            pathStep:[OctagonStateTransitionPathStep pathFromDictionary:obj]];
        }
    }
    return nil;
}
@end


#pragma mark - OctagonStateTransitionWatcher

@interface OctagonStateTransitionWatcher ()
@property BOOL active;
@property BOOL completed;
@property (nullable) OctagonStateTransitionPathStep* remainingPath;
@property NSOperationQueue* operationQueue;

@property (nullable) OctagonStateTransitionRequest* initialRequest;
@property (nullable) CKKSResultOperation* initialTimeoutListenerOp;

@property NSDictionary<OctagonState*, NSNumber*>* stateNumberMap;
@property NSString* unexpectedStateErrorDomain;

@property bool timeoutCanOccur;
@property dispatch_queue_t queue;
@end

@implementation OctagonStateTransitionWatcher

- (instancetype)initNamed:(NSString*)name
             stateMachine:(OctagonStateMachine*)stateMachine
                     path:(OctagonStateTransitionPath*)pathBeginning
           initialRequest:(OctagonStateTransitionRequest* _Nullable)initialRequest
{
    if((self = [super init])) {
        _name = name;
        _intendedPath = pathBeginning;
        _remainingPath = [pathBeginning asPathStep];

        _result = [CKKSResultOperation named:[NSString stringWithFormat:@"watcher-%@", name] withBlock:^{}];
        _operationQueue = [[NSOperationQueue alloc] init];

        // Be careful not to take a strong reference to stateMachine; that'll likely cause a retain loop
        _queue = stateMachine.queue;
        _stateNumberMap = stateMachine.stateNumberMap;
        _unexpectedStateErrorDomain = stateMachine.unexpectedStateErrorDomain;

        _timeoutCanOccur = true;
        _initialRequest = initialRequest;
        if(initialRequest) {
            WEAKIFY(self);
            _initialTimeoutListenerOp = [CKKSResultOperation named:[NSString stringWithFormat:@"watcher-timeout-%@", name] withBlock:^{
                STRONGIFY(self);
                if(!self) {
                    return;
                }

                NSError* opError = initialRequest.transitionOperation.error;

                if(opError &&
                   [opError.domain isEqualToString:CKKSResultErrorDomain] &&
                   opError.code == CKKSResultTimedOut) {
                    dispatch_sync(self.queue, ^{
                        [self _onqueuePerformTimeoutWithUnderlyingError:opError];
                    });
                }
            }];
            [_initialTimeoutListenerOp addDependency:initialRequest.transitionOperation];
            [_operationQueue addOperation:_initialTimeoutListenerOp];
        }

        _active = NO;
        _completed = NO;
    }
    return self;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<OctagonStateTransitionWatcher(%@): remaining: %@, result: %@>",
            self.name,
            self.remainingPath,
            self.result];
}

- (void)onqueueHandleTransition:(CKKSResultOperation<OctagonStateTransitionOperationProtocol>*)attempt
{
    dispatch_assert_queue(self.queue);

    // Early-exit to make error handling better
    if(self.remainingPath == nil || self.completed) {
        return;
    }

    if(self.active) {
        [self onqueueProcessTransition:attempt];

    } else {
        if([attempt.nextState isEqualToString:self.intendedPath.initialState]) {
            self.active = YES;
            [self onqueueProcessTransition:attempt];
        }
    }
}

- (void)_onqueuePerformTimeoutWithUnderlyingError:(NSError* _Nullable)underlyingError
{
    dispatch_assert_queue(self.queue);

    if(self.timeoutCanOccur) {
        self.timeoutCanOccur = false;

        NSString* description = [NSString stringWithFormat:@"Operation(%@) timed out waiting to start for [%@]",
                                 self.name,
                                 self.remainingPath];

        self.result.error = [NSError errorWithDomain:CKKSResultErrorDomain
                                                code:CKKSResultTimedOut
                                         description:description
                                          underlying:underlyingError];
        [self onqueueStartFinishOperation];
    }
}

- (instancetype)timeout:(dispatch_time_t)timeout
{
    WEAKIFY(self);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, timeout), self.queue, ^{
        STRONGIFY(self);
        [self _onqueuePerformTimeoutWithUnderlyingError:nil];
    });

    return self;
}

- (void)onqueueProcessTransition:(CKKSResultOperation<OctagonStateTransitionOperationProtocol>*)attempt
{
    dispatch_assert_queue(self.queue);

    if(self.remainingPath == nil || self.completed) {
        return;
    }

    OctagonStateTransitionPathStep* nextPath = [self.remainingPath nextStep:attempt.nextState];

    if(nextPath) {
        self.remainingPath = nextPath;
        if(self.remainingPath.successState) {
            // We're done!
            [self onqueueStartFinishOperation];
        }

    } else {
        // We're off the path. Error and finish.
        if(attempt.error) {
            self.result.error = attempt.error;
        } else {
            // Do we have an error code for this other state?
            NSNumber* number = self.stateNumberMap[attempt.nextState];
            NSError* underlying = nil;
            if(number != nil) {
                underlying = [NSError errorWithDomain:self.unexpectedStateErrorDomain
                                                 code:[number integerValue]
                                          description:[NSString stringWithFormat:@"unexpected state '%@'", attempt.nextState]];
            }

            self.result.error = [NSError errorWithDomain:OctagonErrorDomain
                                                    code:OctagonErrorUnexpectedStateTransition
                                             description:[NSString stringWithFormat:@"state became %@, was expecting %@", attempt.nextState, self.remainingPath]
                                              underlying:underlying];
        }
        [[CKKSAnalytics logger] logUnrecoverableError:self.result.error
                                             forEvent:OctagonEventStateTransition
                                       withAttributes:@{
                                                        @"name" : self.name,
                                                        @"intended": [self.remainingPath.followStates allKeys],
                                                        @"became" : attempt.nextState,
                                                        }];

        [self onqueueStartFinishOperation];
    }
}

- (void)onqueueStartFinishOperation {
    dispatch_assert_queue(self.queue);

    self.timeoutCanOccur = false;
    [self.operationQueue addOperation:self.result];
    self.active = false;
    self.completed = TRUE;
}

@end

#pragma mark - OctagonStateMultiStateArrivalWatcher

@interface OctagonStateMultiStateArrivalWatcher ()
@property BOOL completed;
@property NSOperationQueue* operationQueue;

@property (nullable) CKKSResultOperation* initialTimeoutListenerOp;

@property bool timeoutCanOccur;
@property dispatch_queue_t queue;
@end


@implementation OctagonStateMultiStateArrivalWatcher
- (instancetype)initNamed:(NSString*)name
              serialQueue:(dispatch_queue_t)queue
                   states:(NSSet<OctagonState*>*)states
{
    return [self initNamed:name
               serialQueue:queue
                    states:states
                failStates:@{}];
}

- (instancetype)initNamed:(NSString*)name
              serialQueue:(dispatch_queue_t)queue
                   states:(NSSet<OctagonState*>*)states
               failStates:(NSDictionary<OctagonState*, NSError*>*)failStates
{
    if((self = [super init])) {
        _name = name;

        _states = [states setByAddingObjectsFromArray:[failStates allKeys]];
        _failStates = failStates;

        _result = [CKKSResultOperation named:[NSString stringWithFormat:@"watcher-%@", name] withBlock:^{}];
        _operationQueue = [[NSOperationQueue alloc] init];

        _queue = queue;
        _timeoutCanOccur = true;

        _completed = NO;
    }
    return self;
}

- (NSString*)description {
    return [NSString stringWithFormat:@"<OctagonStateMultiStateArrivalWatcher(%@): states: %@, result: %@>",
            self.name,
            self.states,
            self.result];
}


- (void)onqueueHandleTransition:(CKKSResultOperation<OctagonStateTransitionOperationProtocol>*)attempt
{
    dispatch_assert_queue(self.queue);
    [self onqueueEnterState:attempt.nextState];
}

- (void)onqueueEnterState:(OctagonState*)state
{
    if(!self.completed) {
        if([self.states containsObject:state]) {
            NSError* possibleError = self.failStates[state];
            [self onqueueStartFinishOperation:possibleError];
        }
    }
}

- (void)_onqueuePerformTimeoutWithUnderlyingError
{
    dispatch_assert_queue(self.queue);

    if(self.timeoutCanOccur) {
        self.timeoutCanOccur = false;

        NSString* description = [NSString stringWithFormat:@"Operation(%@) timed out waiting to start for any state in [%@]",
                                 self.name,
                                 self.states];

        [self onqueueStartFinishOperation:[NSError errorWithDomain:CKKSResultErrorDomain
                                                              code:CKKSResultTimedOut
                                                       description:description]];
    }
}

- (instancetype)timeout:(dispatch_time_t)timeout
{
    WEAKIFY(self);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, timeout), self.queue, ^{
        STRONGIFY(self);
        [self _onqueuePerformTimeoutWithUnderlyingError];
    });

    return self;
}

- (void)onqueueStartFinishOperation:(NSError* _Nullable)resultError
{
    dispatch_assert_queue(self.queue);

    self.timeoutCanOccur = false;
    self.result.error = resultError;
    [self.operationQueue addOperation:self.result];
    self.completed = TRUE;
}

- (void)completeWithErrorIfPending:(NSError*)error
{
    dispatch_sync(self.queue, ^{
        if(!self.completed) {
            [self onqueueStartFinishOperation:error];
        }
    });
}
@end


#endif
