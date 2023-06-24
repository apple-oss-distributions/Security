/*
 * Copyright (c) 2012-2014,2016 Apple Inc. All Rights Reserved.
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

//
//  CKDKVSProxy.m
//  ckd-xpc
//

#import <Foundation/Foundation.h>

#import <utilities/debugging.h>
#import <os/activity.h>

#import "CKDKVSProxy.h"
#import "CKDKVSStore.h"
#import "CKDAKSLockMonitor.h"
#import "CKDSecuritydAccount.h"
#import "NSURL+SOSPlistStore.h"

#include "keychain/SecureObjectSync/SOSARCDefines.h"
#include "keychain/SecureObjectSync/SOSKVSKeys.h"
#include <utilities/SecCFWrappers.h>

#include "SOSCloudKeychainConstants.h"

#include <utilities/SecAKSWrappers.h>
#include <utilities/SecNSAdditions.h>
#import "XPCNotificationDispatcher.h"


@interface NSSet (CKDLogging)
- (NSString*) logKeys;
- (NSString*) logIDs;
@end

@implementation NSSet (CKDLogging)
- (NSString*) logKeys {
    return [self sortedElementsJoinedByString:@" "];
}

- (NSString*) logIDs {
    return [self sortedElementsTruncated:8 JoinedByString:@" "];
}
@end


/*
 The total space available in your app’s iCloud key-value storage is 1 MB.
 The maximum number of keys you can specify is 1024, and the size limit for
 each value associated with a key is 1 MB. So, for example, if you store a
 single large value of 1 MB for a single key, that consumes your total
 available storage. If you store 1 KB of data for each key, you can use
 1,000 key-value pairs.
 */

static NSString *kKeyKeyParameterKeys = @"KeyParameterKeys";
static NSString *kKeyCircleKeys = @"CircleKeys";
static NSString *kKeyMessageKeys = @"MessageKeys";

static NSString *kKeyAlwaysKeys = @"AlwaysKeys";
static NSString *kKeyFirstUnlockKeys = @"FirstUnlockKeys";
static NSString *kKeyUnlockedKeys = @"UnlockedKeys";
static NSString *kKeyPendingKeys = @"PendingKeys";
static NSString *kKeyUnsentChangedKeys = @"unsentChangedKeys";
static NSString *kKeyUnlockNotificationRequested = @"unlockNotificationRequested";
static NSString *kKeySyncWithPeersPending = @"SyncWithPeersPending";

static NSString *kKeyPendingSyncPeerIDs = @"SyncPeerIDs";
static NSString *kKeyPendingSyncBackupPeerIDs = @"SyncBackupPeerIDs";

static NSString *kKeyEnsurePeerRegistration = @"EnsurePeerRegistration";
static NSString *kKeyDSID = @"DSID";
static NSString *kKeyAccountUUID = @"KeyAccountUUID";

static NSString *kMonitorPenaltyBoxKey = @"Penalty";
static NSString *kMonitorMessageKey = @"Message";
static NSString *kMonitorConsecutiveWrites = @"ConsecutiveWrites";
static NSString *kMonitorLastWriteTimestamp = @"LastWriteTimestamp";
static NSString *kMonitorMessageQueue = @"MessageQueue";

static NSString *kMonitorTimeTable = @"TimeTable";
static NSString *kMonitorFirstMinute = @"AFirstMinute";
static NSString *kMonitorSecondMinute = @"BSecondMinute";
static NSString *kMonitorThirdMinute = @"CThirdMinute";
static NSString *kMonitorFourthMinute = @"DFourthMinute";
static NSString *kMonitorFifthMinute = @"EFifthMinute";
static NSString *kMonitorWroteInTimeSlice = @"TimeSlice";

#define kSecServerKeychainChangedNotification "com.apple.security.keychainchanged"

@interface UbiqitousKVSProxy ()
@property (nonatomic) NSDictionary* persistentData;
- (void) doSyncWithAllPeers;
- (void) persistState;
@end

@implementation UbiqitousKVSProxy

+ (instancetype)withAccount:(NSObject<CKDAccount>*) account
                      store:(NSObject<CKDStore>*) store
                lockMonitor:(NSObject<CKDLockMonitor>*) lockMonitor
                persistence:(NSURL*) localPersistence
{
    return [[self alloc] initWithAccount:account
                                   store:store
                             lockMonitor:lockMonitor
                             persistence:localPersistence];
}

- (instancetype)initWithAccount:(NSObject<CKDAccount>*) account
                          store:(NSObject<CKDStore>*) store
                    lockMonitor:(NSObject<CKDLockMonitor>*) lockMonitor
                    persistence:(NSURL*) localPersistence
{
    if (self = [super init])
    {
        secnotice("event", "%@ start UID=%u EUID=%u", self, getuid(), geteuid());
        IF_SOS_DISABLED {
            // bail here if SOS is not supported and somehow this got activated
            secnotice("nosos", "Cannot run CloudKeychainProxy on a system with no SOS");
            return NULL;
        }

#if !TARGET_OS_IPHONE || TARGET_OS_SIMULATOR
        // rdar://problem/26247270
        if (geteuid() == 0) {
            secerror("Cannot run CloudKeychainProxy as root");
            return NULL;
        }
#endif
        _ensurePeerRegistration = NO;

        _pendingSyncPeerIDs = [NSMutableSet set];
        _pendingSyncBackupPeerIDs = [NSMutableSet set];
        _shadowPendingSyncPeerIDs = nil;
        _shadowPendingSyncBackupPeerIDs = nil;

        _persistenceURL = localPersistence;

        _account = account;
        _store = store;
        _lockMonitor = lockMonitor;


        _calloutQueue = dispatch_queue_create("CKDCallout", DISPATCH_QUEUE_SERIAL);
        _ckdkvsproxy_queue = dispatch_queue_create("CKDKVSProxy", DISPATCH_QUEUE_SERIAL);

        _freshnessCompletions = [NSMutableArray<FreshnessResponseBlock> array];

        [[XPCNotificationDispatcher dispatcher] addListener: self];

        [self setPersistentData: [self.persistenceURL readPlist]];

        _dsid =  @"";
        _accountUUID = @"";

        [[self store] connectToProxy: self];
        [[self lockMonitor] connectTo:self];

        secdebug(XPROXYSCOPE, "%@ done", self);
    }
    return self;
}

- (NSString *)description
{
    return [NSString stringWithFormat:@"<%s%s%s%s%s%s%s%s%s%s>",
            [[self lockMonitor] locked] ? "L" : "U",
            [[self lockMonitor] unlockedSinceBoot] ? "B" : "-",
            _seenKVSStoreChange ? "K" : "-",
            [self hasPendingNonShadowSyncIDs] ? "s" : "-",
            _ensurePeerRegistration ? "e" : "-",
            [_pendingKeys count] ? "p" : "-",
            _inCallout ? "C" : "-",
            [self hasPendingShadowSyncIDs] ? "S" : "-",
            _shadowEnsurePeerRegistration ? "E" : "-",
            [_shadowPendingKeys count] ? "P" : "-"];
}

//
// MARK: XPC Function commands
//
- (void) clearStore {
    [self.store removeAllObjects];
}

- (void)synchronizeStore {
    [self.store pushWrites:[NSArray array] requiresForceSync:YES];
}

- (id) objectForKey: (NSString*) key {
    return [self.store objectForKey: key];
}
- (NSDictionary<NSString *, id>*) copyAsDictionary {
    return [self.store copyAsDictionary];
}

- (void)_queue_processAllItems
{
    dispatch_assert_queue(_ckdkvsproxy_queue);

    NSDictionary *allItems = [self.store copyAsDictionary];
    if (allItems)
    {
        secnotice("event", "%@ sending: %@", self, [[allItems allKeys] componentsJoinedByString: @" "]);
        [self processKeyChangedEvent:allItems];
    }
    else
        secdebug(XPROXYSCOPE, "%@ No items in KVS", self);
}

- (void)dealloc
{
    secdebug(XPROXYSCOPE, "%@", self);
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:NSUbiquitousKeyValueStoreDidChangeExternallyNotification
                                                  object:nil];
    
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:NSUbiquityIdentityDidChangeNotification
                                                  object:nil];
}

// MARK: Persistence

- (NSDictionary*) persistentData
{
    return @{ kKeyAlwaysKeys:[_alwaysKeys allObjects],
              kKeyFirstUnlockKeys:[_firstUnlockKeys allObjects],
              kKeyUnlockedKeys:[_unlockedKeys allObjects],
              kKeyPendingKeys:[_pendingKeys allObjects],
              kKeyPendingSyncPeerIDs:[_pendingSyncPeerIDs allObjects],
              kKeyPendingSyncBackupPeerIDs:[_pendingSyncBackupPeerIDs allObjects],
              kKeyEnsurePeerRegistration:[NSNumber numberWithBool:_ensurePeerRegistration],
              kKeyDSID:_dsid,
              kKeyAccountUUID:_accountUUID
              };
}

- (void) setPersistentData: (NSDictionary*) interests
{
    _alwaysKeys = [NSMutableSet setWithArray: interests[kKeyAlwaysKeys]];
    [_alwaysKeys addObject:(__bridge NSString*) kSOSKVSKeyParametersKey];  // Make sure KeyParms are always of interest
    _firstUnlockKeys = [NSMutableSet setWithArray: interests[kKeyFirstUnlockKeys]];
    _unlockedKeys = [NSMutableSet setWithArray: interests[kKeyUnlockedKeys]];

    _pendingKeys = [NSMutableSet setWithArray: interests[kKeyPendingKeys]];

    _pendingSyncPeerIDs = [NSMutableSet setWithArray: interests[kKeyPendingSyncPeerIDs]];
    _pendingSyncBackupPeerIDs = [NSMutableSet setWithArray: interests[kKeyPendingSyncBackupPeerIDs]];

    _ensurePeerRegistration = [interests[kKeyEnsurePeerRegistration] boolValue];

    _dsid = interests[kKeyDSID];
    _accountUUID = interests[kKeyAccountUUID];
    }

- (void)persistState
{
    NSDictionary* dataToSave = self.persistentData;

    secdebug("persistence", "Writing registeredKeys: %@", [dataToSave compactDescription]);
    if (![self.persistenceURL writePlist:dataToSave]) {
        secerror("Failed to write persistence data to %@", self.persistenceURL);
    }
}

- (void)perfCounters:(void(^)(NSDictionary *counters))callback
{
    /* Collect and merge perf counters from other layers here too */
    [self.store perfCounters:callback];
}


// MARK: Object setting


- (void)setStoreObjectsFromDictionary:(NSDictionary *)values
{
    if (values == nil) {
        secdebug(XPROXYSCOPE, "%@ NULL? values: %@", self, values);
        return;
    }

    NSMutableDictionary<NSString*, NSObject*> *mutableValues = [values mutableCopy];
    NSString* newDSID = asNSString([mutableValues extractObjectForKey:(__bridge NSString*) kSOSKVSOfficialDSIDKey]);
    if (newDSID) {
        _dsid = newDSID;
    }

    NSString* requiredDSID = asNSString([mutableValues extractObjectForKey:(__bridge NSString*) kSOSKVSRequiredKey]);
    if (requiredDSID) {
        if (_dsid == nil || [_dsid isEqualToString: @""]) {
            secdebug("dsid", "CloudKeychainProxy setting dsid to :%@ from securityd", requiredDSID);
            _dsid = requiredDSID;
        } else if (![_dsid isEqual: requiredDSID]) {
            secerror("Account DSIDs do not match, cloud keychain proxy: %@, securityd: %@", _dsid, requiredDSID);
            secerror("Not going to write these: %@ into KVS!", values);
            return;
        } else {
            secnoticeq("dsid", "DSIDs match, writing");
        }
    }

    secnoticeq("keytrace", "%@ sending: %@", self, [[mutableValues allKeys] componentsJoinedByString: @" "]);
    [mutableValues enumerateKeysAndObjectsUsingBlock: ^(id key, id obj, BOOL *stop)
     {
         if (obj == NULL || obj == [NSNull null]) {
             [self.store removeObjectForKey:key];
         } else {
             if ([key hasPrefix:@"ak|"]) {  // TODO: somewhat of a hack
                 id oldObj = [self.store objectForKey:key];
                 if ([oldObj isEqual: obj]) {
                     // Fix KVS repeated message undelivery by sending a NULL first (deafness)
                     secnoticeq("keytrace", "forcing resend of key write: %@", key);
                     [self.store removeObjectForKey:key];
                 }
             }
             [[self store] addOneToOutGoing];
             [self.store setObject:obj forKey:key];
         }
    }];

    [self.store pushWrites:[mutableValues allKeys] requiresForceSync:NO];
}

- (void)setObjectsFromDictionary:(NSDictionary<NSString*, NSObject*> *)values
{
    [self setStoreObjectsFromDictionary:values];
}

- (void)waitForSynchronization:(void (^)(NSDictionary<NSString*, NSObject*> *results, NSError *err))handler
{
    secnoticeq("fresh", "%s Requesting WFS", kWAIT2MINID);

    [_freshnessCompletions addObject: ^(bool success, NSError *error){
        secnoticeq("fresh", "%s WFS Done", kWAIT2MINID);
        handler(nil, error);
    }];

    if ([self.freshnessCompletions count] == 1) {
        // We can't talk to synchronize on the _ckdkvsproxy_queue or we deadlock,
        // bounce to a global concurrent queue
        dispatch_after(_nextFreshnessTime, dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSError *error = nil;
            bool success = [self.store pullUpdates:&error];

            dispatch_async(self->_ckdkvsproxy_queue, ^{
                [self waitForSyncDone: success error: error];
            });
        });
    }
}

- (void) waitForSyncDone: (bool) success error: (NSError*) error{
    if (success) {
        const uint64_t delayBeforeCallingAgainInSeconds = 5ull * NSEC_PER_SEC;
        _nextFreshnessTime  = dispatch_time(DISPATCH_TIME_NOW, delayBeforeCallingAgainInSeconds);
    }

    secnoticeq("fresh", "%s Completing WFS", kWAIT2MINID);
    [_freshnessCompletions enumerateObjectsUsingBlock:^(FreshnessResponseBlock _Nonnull block,
                                                        NSUInteger idx,
                                                        BOOL * _Nonnull stop) {
        block(success, error);
    }];
    [_freshnessCompletions removeAllObjects];

}

//
// MARK: ----- KVS key lists -----
//

- (NSMutableSet *)copyAllKeyInterests
{
    NSMutableSet *allKeys = [NSMutableSet setWithSet: _alwaysKeys];
    [allKeys unionSet: _firstUnlockKeys];
    [allKeys unionSet: _unlockedKeys];
    return allKeys;
}

-(void)registerAtTimeKeys:(NSDictionary*)keyparms
{
    if (keyparms == nil)
        return;

    NSArray *alwaysArray = [keyparms valueForKey: kKeyAlwaysKeys];
    NSArray *firstUnlockedKeysArray = [keyparms valueForKey: kKeyFirstUnlockKeys];
    NSArray *whenUnlockedKeysArray = [keyparms valueForKey: kKeyUnlockedKeys];
    
    if(alwaysArray)
        [_alwaysKeys unionSet: [NSMutableSet setWithArray: alwaysArray]];
    if(firstUnlockedKeysArray)
        [_firstUnlockKeys unionSet: [NSMutableSet setWithArray: firstUnlockedKeysArray]];
    if(whenUnlockedKeysArray)
        [_unlockedKeys unionSet: [NSMutableSet setWithArray: whenUnlockedKeysArray]];
}

- (void)removeKeys: (NSArray*)keys forAccount: (NSString*) accountUUID
{
    secdebug(XPROXYSCOPE, "removeKeys: keys: %@", keys);
    
    // We only reset when we know the ID and they send the ID and it changes.
    bool newAccount = accountUUID != nil && self.accountUUID != nil && ![accountUUID isEqualToString: self.accountUUID];
    
    if(newAccount){
        secnotice(XPROXYSCOPE, "not removing keys, account UUID is for a new account");
        return;
    }
    [keys enumerateObjectsUsingBlock:^(NSString*  _Nonnull key, NSUInteger idx, BOOL * _Nonnull stop) {
        secnotice(XPROXYSCOPE, "removing from KVS store: %@", key);
        [self.store removeObjectForKey:key];
    }];
}

- (void)registerKeys: (NSDictionary*)keys forAccount: (NSString*) accountUUID
{
    secdebug(XPROXYSCOPE, "registerKeys: keys: %@", keys);

    // We only reset when we know the ID and they send the ID and it changes.
    bool newAccount = accountUUID != nil && self.accountUUID != nil && ![accountUUID isEqualToString: self.accountUUID];

    if (accountUUID) {
        self.accountUUID = accountUUID;
    }

    // If we're a new account we don't exclude the old keys
    NSMutableSet *allOldKeys = newAccount ? [NSMutableSet set] : [self copyAllKeyInterests];


    NSDictionary *keyparms = [keys valueForKey: [NSString stringWithUTF8String: kMessageKeyParameter]];
    NSDictionary *circles = [keys valueForKey: [NSString stringWithUTF8String: kMessageCircle]];
    NSDictionary *messages = [keys valueForKey: [NSString stringWithUTF8String: kMessageMessage]];
    
    _alwaysKeys = [NSMutableSet set];
    _firstUnlockKeys = [NSMutableSet set];
    _unlockedKeys = [NSMutableSet set];

    [self registerAtTimeKeys: keyparms];
    [self registerAtTimeKeys: circles];
    [self registerAtTimeKeys: messages];

    NSMutableSet *allNewKeys = [self copyAllKeyInterests];
    
    // Make sure keys we no longer care about are not pending
    [_pendingKeys intersectSet:allNewKeys];
    if (_shadowPendingKeys) {
        [_shadowPendingKeys intersectSet:allNewKeys];
    }

    // All new keys only is new keys (remove old keys)
    [allNewKeys minusSet:allOldKeys];

    // Mark new keys pending, they're new!
    NSMutableSet *newKeysForCurrentLockState = [self pendKeysAndGetNewlyPended:allNewKeys];

    [self persistState]; // Before we might call out, save our state so we recover if we crash
    
    [self intersectWithCurrentLockState: newKeysForCurrentLockState];
    // TODO: Don't processPendingKeysForCurrentLockState if none of the new keys have values.
    if ([newKeysForCurrentLockState count] != 0) {
        [self processPendingKeysForCurrentLockState];
    }
}

// MARK: ----- Event Handling -----

- (void)_queue_handleNotification:(const char *) name
{
    dispatch_assert_queue(_ckdkvsproxy_queue);

    if (strcmp(name, kNotifyTokenForceUpdate)==0) {
        // DEBUG -- Possibly remove in future
        [self _queue_processAllItems];
    } else if (strcmp(name, kCloudKeychainStorechangeChangeNotification)==0) {
        // DEBUG -- Possibly remove in future
        [self _queue_kvsStoreChange];
    }
}

- (void)_queue_storeKeysChanged: (NSSet<NSString*>*) changedKeys initial: (bool) initial
{
    dispatch_assert_queue(_ckdkvsproxy_queue);

    // Mark that our store is talking to us, so we don't have to make up for missing anything previous.
    _seenKVSStoreChange = YES;

    // Unmark them as pending as they have just changed and we'll process them.
    [_pendingKeys minusSet:changedKeys];

    // Only send values that we're currently interested in.
    NSSet *keysOfInterestThatChanged = [self pendKeysAndGetPendingForCurrentLockState:changedKeys];
    NSMutableDictionary *changedValues = [self copyValues:keysOfInterestThatChanged];
    if (initial)
        changedValues[(__bridge NSString*)kSOSKVSInitialSyncKey] =  @"true";

    secnotice("event", "%@ keysChangedInCloud: %@ keysOfInterest: %@ initial: %{BOOL}d",
              self,
              [[changedKeys allObjects] componentsJoinedByString: @" "],
              [[changedValues allKeys] componentsJoinedByString: @" "],
              initial);

    if ([changedValues count])
        [self processKeyChangedEvent:changedValues];
}

- (void)_queue_storeAccountChanged
{
    dispatch_assert_queue(_ckdkvsproxy_queue);

    secnotice("event", "%@", self);

    NSDictionary *changedValues = nil;
    if(_dsid)
        changedValues = @{ (__bridge NSString*)kSOSKVSAccountChangedKey: _dsid };
    else
        changedValues = @{ (__bridge NSString*)kSOSKVSAccountChangedKey: @"true" };

    [self processKeyChangedEvent:changedValues];
}

- (void) doAfterFlush: (dispatch_block_t) block
{
    //Flush any pending communication to Securityd.
    if(!_inCallout)
        dispatch_async(_calloutQueue, block);
    else
        _shadowFlushBlock = block;
}

- (void) calloutWith: (void(^)(NSSet *pending, NSSet* pendingSyncIDs, NSSet* pendingBackupSyncIDs, bool ensurePeerRegistration, dispatch_queue_t queue, void(^done)(NSSet *handledKeys, NSSet *handledSyncs, bool handledEnsurePeerRegistration, NSError* error))) callout
{
    // In CKDKVSProxy's serial queue

    // dispatch_get_global_queue - well-known global concurrent queue
    // dispatch_get_main_queue   - default queue that is bound to the main thread
    xpc_transaction_begin();
    dispatch_async(_calloutQueue, ^{
        __block NSSet *myPending;
        __block NSSet *mySyncPeerIDs;
        __block NSSet *mySyncBackupPeerIDs;
        __block bool myEnsurePeerRegistration;
        __block bool wasLocked;
        dispatch_sync(self->_ckdkvsproxy_queue, ^{
            myPending = [self->_pendingKeys copy];
            mySyncPeerIDs = [self->_pendingSyncPeerIDs copy];
            mySyncBackupPeerIDs = [self->_pendingSyncBackupPeerIDs copy];

            myEnsurePeerRegistration = self->_ensurePeerRegistration;
            wasLocked = [self.lockMonitor locked];

            self->_inCallout = YES;

            self->_shadowPendingKeys = [NSMutableSet set];
            self->_shadowPendingSyncPeerIDs = [NSMutableSet set];
            self->_shadowPendingSyncBackupPeerIDs = [NSMutableSet set];
        });

        callout(myPending, mySyncPeerIDs, mySyncBackupPeerIDs, myEnsurePeerRegistration, self->_ckdkvsproxy_queue, ^(NSSet *handledKeys, NSSet *handledSyncs, bool handledEnsurePeerRegistration, NSError* failure) {
            secdebug("event", "%@ %s%s before callout handled: %s%s", self,
                     ![mySyncPeerIDs isEmpty] || ![mySyncBackupPeerIDs isEmpty] ? "S" : "s",
                     myEnsurePeerRegistration ? "E" : "e",
                     ![handledKeys isEmpty] ? "S" : "s",
                     handledEnsurePeerRegistration ? "E" : "e");
            
            // In CKDKVSProxy's serial queue
            self->_inCallout = NO;

            // Update ensurePeerRegistration
            self->_ensurePeerRegistration = ((self->_ensurePeerRegistration && !handledEnsurePeerRegistration) || self->_shadowEnsurePeerRegistration);
            
            self->_shadowEnsurePeerRegistration = NO;

            [self handlePendingEnsurePeerRegistrationRequests:true];

            bool hadShadowPeerIDs = ![self->_shadowPendingSyncPeerIDs isEmpty] || ![self->_shadowPendingSyncBackupPeerIDs isEmpty];

            // Update SyncWithPeers stuff.
            if (handledSyncs) {
                [self->_pendingSyncPeerIDs minusSet: handledSyncs];
                [self->_pendingSyncBackupPeerIDs minusSet: handledSyncs];

                if (![handledSyncs isEmpty]) {
                    secnotice("sync-ids", "handled syncIDs: %@", [handledSyncs logIDs]);
                    secnotice("sync-ids", "remaining peerIDs: %@", [self->_pendingSyncPeerIDs logIDs]);
                    secnotice("sync-ids", "remaining backupIDs: %@", [self->_pendingSyncBackupPeerIDs logIDs]);

                    if (hadShadowPeerIDs) {
                        secnotice("sync-ids", "signaled peerIDs: %@", [self->_shadowPendingSyncPeerIDs logIDs]);
                        secnotice("sync-ids", "signaled backupIDs: %@", [self->_shadowPendingSyncBackupPeerIDs logIDs]);
                    }
                }

                self->_shadowPendingSyncPeerIDs = nil;
                self->_shadowPendingSyncBackupPeerIDs = nil;
            }


            // Update pendingKeys and handle them
            [self->_pendingKeys removeObject: [NSNull null]]; // Don't let NULL hang around

            [self->_pendingKeys minusSet: handledKeys];
            bool hadShadowPendingKeys = [self->_shadowPendingKeys count];
            // Move away shadownPendingKeys first, because pendKeysAndGetPendingForCurrentLockState
            // will look at them. See rdar://problem/20733166.
            NSSet *oldShadowPendingKeys = self->_shadowPendingKeys;
            self->_shadowPendingKeys = nil;

            NSSet *filteredKeys = [self pendKeysAndGetPendingForCurrentLockState:oldShadowPendingKeys];

            secnoticeq("keytrace", "%@ account handled: %@ pending: %@", self,
                       [[handledKeys allObjects] componentsJoinedByString: @" "],
                       [[filteredKeys allObjects] componentsJoinedByString: @" "]);

            // Write state to disk
            [self persistState];

            // Handle shadow pended stuff

            // We only kick off another sync if we got new stuff during handling
            if (hadShadowPeerIDs && ![self.lockMonitor locked]) {
                secnotice("event", "%@ syncWithPeersPending: %d inCallout: %d isLocked: %d", self, [self hasPendingSyncIDs], self->_inCallout, [self.lockMonitor locked]);
                if ([self hasPendingSyncIDs] && !self->_inCallout && ![self.lockMonitor locked]){
                    [self doSyncWithPendingPeers];
                }
            }

            /* We don't want to call processKeyChangedEvent if we failed to
             handle pending keys and the device didn't unlock nor receive
             any kvs changes while we were in our callout.
             Doing so will lead to securityd and CloudKeychainProxy
             talking to each other forever in a tight loop if securityd
             repeatedly returns an error processing the same message.
             Instead we leave any old pending keys until the next event. */
            if (hadShadowPendingKeys || (![self.lockMonitor locked] && wasLocked)){
                [self processKeyChangedEvent:[self copyValues:filteredKeys]];
                if(self->_shadowFlushBlock != NULL)
                    secerror("Flush block is not null and sending new keys");
            }

            if(self->_shadowFlushBlock != NULL){
                dispatch_async(self->_calloutQueue, self->_shadowFlushBlock);
                self->_shadowFlushBlock = NULL;
            }

            if (failure) {
                [self.lockMonitor recheck];
            }
            
            xpc_transaction_end();
        });
    });
}

- (void) sendKeysCallout: (NSSet *(^)(NSSet* pending, NSError** error)) handleKeys {
    [self calloutWith: ^(NSSet *pending, NSSet* pendingSyncIDs, NSSet* pendingBackupSyncIDs, bool ensurePeerRegistration, dispatch_queue_t queue, void(^done)(NSSet *handledKeys, NSSet *handledSyncs, bool handledEnsurePeerRegistration, NSError* error)) {
        NSError* error = NULL;

        secnotice("CloudKeychainProxy", "send keys: %@", pending);
        NSSet * handled = handleKeys(pending, &error);

        dispatch_async(queue, ^{
            if (!handled) {
                secerror("%@ ensurePeerRegistration failed: %@", self, error);
            }

            done(handled, nil, NO, error);
        });
    }];
}

- (void)handlePendingEnsurePeerRegistrationRequests:(bool)onlyIfUnlocked
{
    // doEnsurePeerRegistration's callback will be run on _calloutQueue, so we should check the 'are we running yet' flags on that queue
    dispatch_async(_calloutQueue, ^{
        if(self.ensurePeerRegistration && (!onlyIfUnlocked || ![self.lockMonitor locked])) {
            if(self.ensurePeerRegistrationEnqueuedButNotStarted) {
                secnotice("EnsurePeerRegistration", "%@ ensurePeerRegistration block already enqueued, not starting a new one", self);
                return;
            }

            [self doEnsurePeerRegistration];
        }
    });
}

- (void) doEnsurePeerRegistration
{
    NSObject<CKDAccount>* accountDelegate = [self account];
    self.ensurePeerRegistrationEnqueuedButNotStarted = true;
    [self calloutWith:^(NSSet *pending, NSSet* pendingSyncIDs, NSSet* pendingBackupSyncIDs, bool ensurePeerRegistration, dispatch_queue_t queue, void(^done)(NSSet *handledKeys, NSSet *handledSyncs, bool handledEnsurePeerRegistration, NSError* error)) {
        NSError* error = nil;
        self.ensurePeerRegistrationEnqueuedButNotStarted = false;
        bool handledEnsurePeerRegistration = [accountDelegate ensurePeerRegistration:&error];
        secnotice("EnsurePeerRegistration", "%@ ensurePeerRegistration called, %@ (%@)", self, handledEnsurePeerRegistration ? @"success" : @"failure", error);
        if (!handledEnsurePeerRegistration) {
            [self.lockMonitor recheck];
            handledEnsurePeerRegistration = ![self.lockMonitor locked]; // If we're unlocked we handled it, if we're locked we didn't.
                                                              // This means we get to fail once per unlock and then cut that spinning out.
        }
        dispatch_async(queue, ^{
            done(nil, nil, handledEnsurePeerRegistration, error);
        });
    }];
}

- (void) doSyncWithPendingPeers
{
    NSObject<CKDAccount>* accountDelegate = [self account];
    [self calloutWith:^(NSSet *pending, NSSet* pendingSyncIDs, NSSet* pendingBackupSyncIDs, bool ensurePeerRegistration, dispatch_queue_t queue, void(^done)(NSSet *handledKeys, NSSet *handledSyncs, bool handledEnsurePeerRegistration, NSError* error)) {
        NSError* error = NULL;
        secnotice("syncwith", "%@ syncwith peers: %@", self, [[pendingSyncIDs allObjects] componentsJoinedByString:@" "]);
        secnotice("syncwith", "%@ syncwith backups: %@", self, [[pendingBackupSyncIDs allObjects] componentsJoinedByString:@" "]);
        NSSet<NSString*>* handled = [accountDelegate syncWithPeers:pendingSyncIDs backups:pendingBackupSyncIDs error:&error];
        secnotice("syncwith", "%@ syncwith handled: %@", self, [[handled allObjects] componentsJoinedByString:@" "]);
        dispatch_async(queue, ^{
            if (!handled) {
                // We might be confused about lock state
                [self.lockMonitor recheck];
            }

            done(nil, handled, false, error);
        });
    }];
}

- (void) doSyncWithAllPeers
{
    NSObject<CKDAccount>* accountDelegate = [self account];
    [self calloutWith:^(NSSet *pending, NSSet* pendingSyncIDs, NSSet* pendingBackupSyncIDs, bool ensurePeerRegistration, dispatch_queue_t queue, void(^done)(NSSet *handledKeys, NSSet *handledSyncs, bool handledEnsurePeerRegistration, NSError*error)) {
        NSError* error = NULL;
        bool handled = [accountDelegate syncWithAllPeers:&error];
        if (!handled) {
            secerror("Failed to syncWithAllPeers: %@", error);
        }
        dispatch_async(queue, ^{
            done(nil, nil, false, error);
        });
    }];
}

- (bool)hasPendingNonShadowSyncIDs {
    return ![_pendingSyncPeerIDs isEmpty] || ![_pendingSyncBackupPeerIDs isEmpty];
}

- (bool)hasPendingShadowSyncIDs {
    return (_shadowPendingSyncPeerIDs && ![_shadowPendingSyncPeerIDs isEmpty]) ||
    (_shadowPendingSyncBackupPeerIDs && ![_shadowPendingSyncBackupPeerIDs isEmpty]);
}

- (bool)hasPendingSyncIDs
{
    bool pendingIDs = [self hasPendingNonShadowSyncIDs];

    if (_inCallout) {
        pendingIDs |= [self hasPendingShadowSyncIDs];
    }

    return pendingIDs;
}

- (void)requestSyncWithPeerIDs: (NSArray<NSString*>*) peerIDs backupPeerIDs: (NSArray<NSString*>*) backupPeerIDs
{
    if ([peerIDs count] == 0 && [backupPeerIDs count] == 0)
        return; // Nothing to do;

    NSSet<NSString*>* peerIDsSet = [NSSet setWithArray: peerIDs];
    NSSet<NSString*>* backupPeerIDsSet = [NSSet setWithArray: backupPeerIDs];

    [_pendingSyncPeerIDs unionSet: peerIDsSet];
    [_pendingSyncBackupPeerIDs unionSet: backupPeerIDsSet];

    if (_inCallout) {
        [_shadowPendingSyncPeerIDs unionSet: peerIDsSet];
        [_shadowPendingSyncBackupPeerIDs unionSet: backupPeerIDsSet];
    }

    [self persistState];

    [self handlePendingEnsurePeerRegistrationRequests:true];

    if ([self hasPendingSyncIDs] && !_inCallout && ![self.lockMonitor locked]){
        [self doSyncWithPendingPeers];
    }
}

- (BOOL)hasSyncPendingFor: (NSString*) peerID {
    return [_pendingSyncPeerIDs containsObject: peerID] ||
    (_shadowPendingSyncPeerIDs && [_shadowPendingSyncPeerIDs containsObject: peerID]);
}

- (BOOL)hasPendingKey: (NSString*) keyName {
    return [self.pendingKeys containsObject: keyName]
        || (_shadowPendingKeys && [self.shadowPendingKeys containsObject: keyName]);
}

- (void)requestEnsurePeerRegistration
{
#if !defined(NDEBUG)
    NSString *desc = [self description];
#endif
    
    if (_inCallout) {
        _shadowEnsurePeerRegistration = YES;
    } else {
        _ensurePeerRegistration = YES;
        [self handlePendingEnsurePeerRegistrationRequests:true];
        [self persistState];
    }
    
    secdebug("event", "%@ %@", desc, self);
}

- (void)_queue_locked
{
    dispatch_assert_queue(_ckdkvsproxy_queue);

    secnotice("event", "%@ Locked", self);
}

- (void)_queue_unlocked
{
    dispatch_assert_queue(_ckdkvsproxy_queue);

    secnotice("event", "%@ Unlocked", self);
    [self handlePendingEnsurePeerRegistrationRequests:false];
    
    // First send changed keys to securityd so it can proccess updates
    [self processPendingKeysForCurrentLockState];
    
    // Then, tickle securityd to perform a sync if needed.
    if ([self hasPendingSyncIDs]) {
        [self doSyncWithPendingPeers];
    }
}

- (void) _queue_kvsStoreChange {
    dispatch_assert_queue(_ckdkvsproxy_queue);

    os_activity_initiate("kvsStoreChange", OS_ACTIVITY_FLAG_DEFAULT, ^{
        if (!self->_seenKVSStoreChange) {
            secnotice("event", "%@ received darwin notification before first NSNotification", self);
            // TODO This might not be needed if we always get the NSNotification
            // deleived even if we were launched due to a kvsStoreChange
            // Send all keys for current lock state to securityd so it can proccess them
            [self pendKeysAndGetNewlyPended: [self copyAllKeyInterests]];
            [self processPendingKeysForCurrentLockState];
        } else {
            secdebug("event", "%@ ignored, waiting for NSNotification", self);
        }
    });
}

#pragma mark -
#pragma mark XPCNotificationListener

- (void)handleNotification:(const char *) name
{
    // sync because we cannot ensure the lifetime of name
    dispatch_sync(_ckdkvsproxy_queue, ^{
        [self _queue_handleNotification:name];
    });
}

#pragma mark -
#pragma mark Calls from -[CKDKVSStore kvsStoreChanged:]

- (void)storeKeysChanged: (NSSet<NSString*>*) changedKeys initial: (bool) initial
{
    // sync, caller must wait to ensure correct state
    dispatch_sync(_ckdkvsproxy_queue, ^{
        [self _queue_storeKeysChanged:changedKeys initial:initial];
    });
}

- (void)storeAccountChanged
{
    // sync, caller must wait to ensure correct state
    dispatch_sync(_ckdkvsproxy_queue, ^{
        [self _queue_storeAccountChanged];
    });
}

#pragma mark -
#pragma mark CKDLockListener

- (void) locked
{
    // sync, otherwise tests fail
    dispatch_sync(_ckdkvsproxy_queue, ^{
        [self _queue_locked];
    });
}

- (void) unlocked
{
    // sync, otherwise tests fail
    dispatch_sync(_ckdkvsproxy_queue, ^{
        [self _queue_unlocked];
    });
}

//
// MARK: ----- Key Filtering -----
//

- (NSSet*) keysForCurrentLockState
{
    secdebug("filtering", "%@ Filtering: unlockedSinceBoot: %d\n unlocked: %d\n, keysOfInterest: <%@>", self, (int) [self.lockMonitor unlockedSinceBoot], (int) ![self.lockMonitor locked], [self.persistentData compactDescription]);

    NSMutableSet *currentStateKeys = [NSMutableSet setWithSet: _alwaysKeys];
    if ([self.lockMonitor unlockedSinceBoot])
        [currentStateKeys unionSet: _firstUnlockKeys];
    
    if (![self.lockMonitor locked])
        [currentStateKeys unionSet: _unlockedKeys];
    
    return currentStateKeys;
}


- (NSMutableSet*) pendKeysAndGetNewlyPended: (NSSet*) keysToPend
{
    NSMutableSet *filteredKeysToPend = [self copyAllKeyInterests];
    [filteredKeysToPend intersectSet: keysToPend];
    
    NSMutableSet *newlyPendedKeys = [filteredKeysToPend mutableCopy];
    [newlyPendedKeys minusSet: _pendingKeys];
    if (_shadowPendingKeys) {
        [newlyPendedKeys minusSet: _shadowPendingKeys];
    }
    
    if (_shadowPendingKeys) {
        [_shadowPendingKeys unionSet:filteredKeysToPend];
    }
    else{
        [_pendingKeys unionSet:filteredKeysToPend];
    }
    
    return newlyPendedKeys;
}

- (void) intersectWithCurrentLockState: (NSMutableSet*) set
{
    [set intersectSet: [self keysForCurrentLockState]];
}

- (NSMutableSet*) pendingKeysForCurrentLockState
{
    NSMutableSet * result = [_pendingKeys mutableCopy];
    [self intersectWithCurrentLockState:result];
    return result;
}

- (NSMutableSet*) pendKeysAndGetPendingForCurrentLockState: (NSSet*) startingSet
{
    [self pendKeysAndGetNewlyPended: startingSet];
    
    return [self pendingKeysForCurrentLockState];
}

- (NSMutableDictionary *)copyValues:(NSSet*)keysOfInterest
{
    // Grab values from store.
    NSObject<CKDStore> *store = [self store];
    NSMutableDictionary *changedValues = [NSMutableDictionary dictionaryWithCapacity:0];
    [keysOfInterest enumerateObjectsUsingBlock:^(id obj, BOOL *stop)
     {
         NSString* key = (NSString*) obj;
         id objval = [store objectForKey:key];
         if (!objval) objval = [NSNull null];
         
         [changedValues setObject:objval forKey:key];
         secdebug(XPROXYSCOPE, "%@ storeChanged updated value for %@", self, key);
     }];
    return changedValues;
}

/*
 During RegisterKeys, separate keys-of-interest into three disjoint sets:
 - keys that we always want to be notified about; this means we can get the
 value at any time
 - keys that require the device to have been unlocked at least once
 - keys that require the device to be unlocked now
 
 Typically, the sets of keys will be:
 
 - Dk: alwaysKeys
 - Ck: firstUnlock
 - Ak: unlocked
 
 The caller is responsible for making sure that the keys in e.g. alwaysKeys are
 values that can be handled at any time (that is, not when unlocked)
 
 Each time we get a notification from ubiquity that keys have changed, we need to
 see if anything of interest changed. If we don't care, then done.
 
 For each key-of-interest that changed, we either notify the client that things
 changed, or add it to a pendingNotifications list. If the notification to the
 client fails, also add it to the pendingNotifications list. This pending list
 should be written to persistent storage and consulted any time we either get an
 item changed notification, or get a stream event signalling a change in lock state.
 
 We can notify the client either through XPC if a connection is set up, or call a
 routine in securityd to launch it.
 
 */

- (void)processKeyChangedEvent:(NSDictionary *)changedValues
{
    NSMutableDictionary* filtered = [NSMutableDictionary dictionary];

    secnotice("processKeyChangedEvent", "changedValues:%@", changedValues);
    NSMutableArray* nullKeys = [NSMutableArray array];
    // Remove nulls because we don't want them in securityd.
    [changedValues enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
        if (obj == [NSNull null]){
            [nullKeys addObject:key];
        }else{
            filtered[key] = obj;
        }
    }];
    if ([nullKeys count])
        [_pendingKeys minusSet: [NSSet setWithArray: nullKeys]];
    
    if([filtered count] != 0 ) {
        [self sendKeysCallout:^NSSet *(NSSet *pending, NSError** error) {
            secnotice("processing keys", "pending:%@", pending);
            NSError *updateError = nil;
            return [[self account] keysChanged: filtered error: &updateError];
        }];
    } else {
        secnoticeq("keytrace", "%@ null: %@ pending: %@", self,
                  [nullKeys componentsJoinedByString: @" "],
                  [[_pendingKeys allObjects] componentsJoinedByString: @" "]);
    }
}

- (void) processPendingKeysForCurrentLockState
{
    [self processKeyChangedEvent: [self copyValues: [self pendingKeysForCurrentLockState]]];
}

@end


