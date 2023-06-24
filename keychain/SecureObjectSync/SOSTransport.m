
#include "keychain/SecureObjectSync/SOSInternal.h"
#include "keychain/SecureObjectSync/SOSKVSKeys.h"
#include "keychain/SecureObjectSync/SOSAccountPriv.h"
#include "keychain/SecureObjectSync/SOSTransport.h"
#include "keychain/SecureObjectSync/SOSTransportKeyParameter.h"
#include "keychain/SecureObjectSync/SOSTransportCircleKVS.h"
#include "keychain/SecureObjectSync/SOSTransportMessageKVS.h"
#include "keychain/SecureObjectSync/SOSTransportMessage.h"
#include "keychain/SecureObjectSync/SOSRing.h"
#include <keychain/SecureObjectSync/SOSDictionaryUpdate.h>
#include <Security/SecureObjectSync/SOSCloudCircleInternal.h>


#include "keychain/SecureObjectSync/CKBridge/SOSCloudKeychainClient.h"
#include <utilities/debugging.h>
#include <utilities/SecCFWrappers.h>
#include <CoreFoundation/CFBase.h>


CFStringRef kKeyParameter = CFSTR("KeyParameter");
CFStringRef kCircle = CFSTR("Circle");
CFStringRef kMessage = CFSTR("Message");
CFStringRef kAlwaysKeys = CFSTR("AlwaysKeys");
CFStringRef kFirstUnlocked = CFSTR("FirstUnlockKeys");
CFStringRef kUnlocked = CFSTR("UnlockedKeys");
extern CFStringRef kSOSAccountDebugScope;

#define DATE_LENGTH 18

CFStringRef SOSInterestListCopyDescription(CFArrayRef interests)
{
    CFMutableStringRef description = CFStringCreateMutable(kCFAllocatorDefault, 0);
    CFStringAppendFormat(description, NULL, CFSTR("<Interest: "));
    
    if (interests) {
        CFArrayForEach(interests, ^(const void* string) {
            if (isString(string))
             
                CFStringAppendFormat(description, NULL, CFSTR(" '%@'"), string);
        });
    }
    CFStringAppend(description, CFSTR(">"));

    return description;
}


//
// MARK: Key Interest Processing
//

CFGiblisGetSingleton(CFMutableArrayRef, SOSGetTransportMessages, sTransportMessages,  ^{
    *sTransportMessages = CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
});

CFGiblisGetSingleton(CFMutableArrayRef, SOSGetTransportKeyParameters, sTransportKeyParameters,  ^{
    *sTransportKeyParameters = CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
});

CFGiblisGetSingleton(CFMutableArrayRef, SOSGetTransportCircles, sTransportCircles,  ^{
    *sTransportCircles = CFArrayCreateMutable(kCFAllocatorDefault, 0, NULL);
});


void SOSRegisterTransportMessage(SOSMessage* additional) {
    if(additional != nil)
        CFArrayAppendValue(SOSGetTransportMessages(), (__bridge CFTypeRef)(additional));
}

void SOSUnregisterTransportMessage(SOSMessage* removal) {
    CFArrayRemoveAllValue(SOSGetTransportMessages(), (__bridge CFTypeRef)(removal));
}

void SOSUnregisterAllTransportMessages(void) {
    CFArrayRemoveAllValues(SOSGetTransportMessages());
}

void SOSRegisterTransportCircle(SOSCircleStorageTransport* additional) {
    if(additional != nil)
        CFArrayAppendValue(SOSGetTransportCircles(), (__bridge CFTypeRef)(additional));
}

void SOSUnregisterTransportCircle(SOSCircleStorageTransport* removal) {
    CFArrayRemoveAllValue(SOSGetTransportCircles(), (__bridge CFTypeRef)removal);
}

void SOSUnregisterAllTransportCircles(void) {
    CFArrayRemoveAllValues(SOSGetTransportCircles());
}

void SOSRegisterTransportKeyParameter(CKKeyParameter* additional) {
    if(additional != nil)
        CFArrayAppendValue(SOSGetTransportKeyParameters(), (__bridge CFTypeRef)(additional));
}

void SOSUnregisterTransportKeyParameter(CKKeyParameter* removal) {
    CFArrayRemoveAllValue(SOSGetTransportKeyParameters(), (__bridge CFTypeRef)(removal));
}

void SOSUnregisterAllTransportKeyParameters(void) {
    CFArrayRemoveAllValues(SOSGetTransportKeyParameters());
}

//
// Should we be dispatching back to our queue to handle later
//
void SOSUpdateKeyInterest(SOSAccount* account)
{
    CFMutableArrayRef alwaysKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableArrayRef afterFirstUnlockKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableArrayRef whenUnlockedKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableDictionaryRef keyDict = CFDictionaryCreateMutableForCFTypes (kCFAllocatorDefault);
    static SOSDictionaryUpdate *keyDictStatus = NULL;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        keyDictStatus = [SOSDictionaryUpdate new];
    });

    NSMutableArray *temp = (__bridge NSMutableArray *)(SOSGetTransportKeyParameters());

    [temp enumerateObjectsUsingBlock:^(CKKeyParameter *value, NSUInteger idx, BOOL * _Nonnull stop) {
        CKKeyParameter* tKP = (CKKeyParameter*) value;
        if ([tKP SOSTransportKeyParameterGetAccount:tKP] == account && [tKP SOSTransportKeyParameterGetTransportType:tKP err:NULL] == kKVS) {
            CKKeyParameter* tkvs = (CKKeyParameter*) value;
            CFErrorRef localError = NULL;

            if (![tkvs SOSTransportKeyParameterKVSAppendKeyInterests:tkvs ak:alwaysKeys firstUnLock:afterFirstUnlockKeys unlocked:whenUnlockedKeys err:&localError]) {
                secnotice("key-interests", "Error getting key parameters interests %@", localError);
            }
            CFReleaseNull(localError);
        }

    }];
    
    CFMutableDictionaryRef keyParamsDict = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFDictionarySetValue(keyParamsDict, kAlwaysKeys, alwaysKeys);
    CFDictionarySetValue(keyParamsDict, kFirstUnlocked, afterFirstUnlockKeys);
    CFDictionarySetValue(keyParamsDict, kUnlocked, whenUnlockedKeys);
    CFDictionarySetValue(keyDict, kKeyParameter, keyParamsDict);

    CFReleaseNull(alwaysKeys);
    CFReleaseNull(afterFirstUnlockKeys);
    CFReleaseNull(whenUnlockedKeys);
    alwaysKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    afterFirstUnlockKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    whenUnlockedKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    
    CFArrayForEach(SOSGetTransportCircles(), ^(const void *value) {
        SOSKVSCircleStorageTransport *transport = (__bridge SOSKVSCircleStorageTransport*)value;
        if ( [[transport getAccount] isEqual: account] ) {
            SOSKVSCircleStorageTransport* tkvs = (__bridge SOSKVSCircleStorageTransport*) value;
            CFErrorRef localError = NULL;

            if(! [tkvs kvsAppendKeyInterest:alwaysKeys firstUnlock:afterFirstUnlockKeys unlocked:whenUnlockedKeys err:&localError]){
                secnotice("key-interests", "Error getting circle interests %@", localError);
            }
            if(![tkvs kvsAppendRingKeyInterest:alwaysKeys firstUnlock:afterFirstUnlockKeys unlocked:whenUnlockedKeys err:&localError]){
                secnotice("key-interests", "Error getting ring interests %@", localError);
            }
            if(![tkvs kvsAppendDebugKeyInterest:alwaysKeys firstUnlock:afterFirstUnlockKeys unlocked:whenUnlockedKeys err:&localError]) {
                secnotice("key-interests", "Error getting debug key interests %@", localError);
            }
            
            CFReleaseNull(localError);
        }
        
    });
    CFMutableDictionaryRef circleDict = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFDictionarySetValue(circleDict, kAlwaysKeys, alwaysKeys);
    CFDictionarySetValue(circleDict, kFirstUnlocked, afterFirstUnlockKeys);
    CFDictionarySetValue(circleDict, kUnlocked, whenUnlockedKeys);
    CFDictionarySetValue(keyDict, kCircle, circleDict);
    
    CFReleaseNull(alwaysKeys);
    CFReleaseNull(afterFirstUnlockKeys);
    CFReleaseNull(whenUnlockedKeys);
    alwaysKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    afterFirstUnlockKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    whenUnlockedKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    
    CFArrayForEach(SOSGetTransportMessages(), ^(const void *value) {
        SOSMessage* transport = (__bridge SOSMessage*)value;
        if ([transport SOSTransportMessageGetAccount] == account && [transport SOSTransportMessageGetTransportType] == kKVS) {
            CFErrorRef localError = NULL;
            SOSMessageKVS* tks = (__bridge SOSMessageKVS*)value;
            if(![tks SOSTransportMessageKVSAppendKeyInterest:tks ak:alwaysKeys firstUnlock:afterFirstUnlockKeys unlocked:whenUnlockedKeys err:&localError]){
                secnotice("key-interests", "Error getting message interests %@", localError);
            }
            CFReleaseNull(localError);
        }
    });
    
    CFMutableDictionaryRef messageDict = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFDictionarySetValue(messageDict, kAlwaysKeys, alwaysKeys);
    CFDictionarySetValue(messageDict, kFirstUnlocked, afterFirstUnlockKeys);
    CFDictionarySetValue(messageDict, kUnlocked, whenUnlockedKeys);
    CFDictionarySetValue(keyDict, kMessage, messageDict);

    bool pushInterests = [keyDictStatus hasChanged:keyDict];

    secnotice("key-interests", "Calculating interests done: %s", pushInterests ? "Registering with CKP": "No Change, Ignoring");

    if(pushInterests) {
        //
        // Log what we are about to do.
        //
        NSUInteger itemCount = 0;
        for (NSString *subsystem in @[(__bridge id)kMessage, (__bridge id)kCircle, (__bridge id)kKeyParameter]) {
            secnotice("key-interests", "Updating interests: %@", subsystem);
            for (NSString *lockState in @[(__bridge id)kAlwaysKeys, (__bridge id)kFirstUnlocked, (__bridge id)kUnlocked]) {
                NSArray *items = ((__bridge NSDictionary *)keyDict)[subsystem][lockState];
                itemCount += items.count;
                for (NSString *item in items) {
                    secnotice("key-interests", " key-intrest: %@->%@: %@", subsystem, lockState, item);
                }
            }
        }
        secnotice("key-interests", "Pushing %lu interests to CKP", (unsigned long)itemCount);

        CFStringRef uuid = SOSAccountCopyUUID(account);
        SOSCloudKeychainUpdateKeys(keyDict, uuid, dispatch_get_global_queue(SOS_TRANSPORT_PRIORITY, 0), ^(CFDictionaryRef returnedValues, CFErrorRef error) {
            if (error) {
                secnotice("key-interests", "Error updating keys: %@", error);
                account.key_interests_need_updating = true;
                [keyDictStatus reset];
            } else {
                account.key_interests_need_updating = false;
            }
        });
        CFReleaseNull(uuid);
    } else { // no change detected, no failure, so no need to retry
        account.key_interests_need_updating = false;
    }

    CFReleaseNull(alwaysKeys);
    CFReleaseNull(afterFirstUnlockKeys);
    CFReleaseNull(whenUnlockedKeys);
    CFReleaseNull(keyParamsDict);
    CFReleaseNull(circleDict);
    CFReleaseNull(messageDict);
    CFReleaseNull(keyDict);
}


static void showWhatWasHandled(CFDictionaryRef updates, CFMutableArrayRef handledKeys) {
    
    CFMutableStringRef updateStr = CFStringCreateMutable(kCFAllocatorDefault, 0);
    CFMutableStringRef handledKeysStr = CFStringCreateMutable(kCFAllocatorDefault, 0);
    
    CFDictionaryForEach(updates, ^(const void *key, const void *value) {
        if (isString(key)) {
            CFStringAppendFormat(updateStr, NULL, CFSTR("%@ "), (CFStringRef)key);
        }
    });
    CFArrayForEach(handledKeys, ^(const void *value) {
        if (isString(value)) {
            CFStringAppendFormat(handledKeysStr, NULL, CFSTR("%@ "), (CFStringRef)value);
        }
    });
    secinfo("updates", "Updates [%ld]: %@", CFDictionaryGetCount(updates), updateStr);
    secinfo("updates", "Handled [%ld]: %@", CFArrayGetCount(handledKeys), handledKeysStr);
    
    CFReleaseSafe(updateStr);
    CFReleaseSafe(handledKeysStr);
}

#define KVS_STATE_INTERVAL 50

static bool sosDisabledRingException(CFStringRef ringName) {
    bool retval = false;
    if(CFEqual(ringName, CFSTR("iCloudIdentity-tomb")) || CFEqual(ringName, CFSTR("PCS-MasterKey-tomb")) || CFEqual(ringName, kSOSRecoveryRing)) {
        retval = true;
    }
    return retval;
}

CF_RETURNS_RETAINED
CFMutableArrayRef SOSTransportDispatchMessages(SOSAccountTransaction* txn, CFDictionaryRef updates, CFErrorRef *error){
    __block SOSAccount* account = txn.account;
    
    IF_SOS_DISABLED {
        secnotice("nosos", "got message for sos and the system is off");
        return NULL;
    }

    CFMutableArrayRef handledKeys = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    CFStringRef dsid = NULL;
    
    if(CFDictionaryGetValueIfPresent(updates, kSOSKVSAccountChangedKey, (const void**)&dsid)){
        secnotice("accountChange", "SOSTransportDispatchMessages received kSOSKVSAccountChangedKey");
        // While changing accounts we may modify the key params array. To avoid stepping on ourselves we
        // copy the list for iteration.  Now modifying the transport outside of the list iteration.
        CFMutableArrayRef transportsToUse = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
        
        CFArrayForEach(SOSGetTransportKeyParameters(), ^(const void *value) {
            CKKeyParameter* transport = (__bridge CKKeyParameter*) value;

            if(CFEqualSafe((__bridge CFTypeRef)([transport SOSTransportKeyParameterGetAccount:transport]), (__bridge CFTypeRef)(account))){
                CFArrayAppendValue(transportsToUse, (__bridge const void *)(transport));
            }
        });
        
        SOSAccountAssertDSID(account, dsid);
        CFReleaseNull(transportsToUse);
    
        CFArrayAppendValue(handledKeys, kSOSKVSAccountChangedKey);
    }

    
    // Iterate through keys in updates.  Perform circle change update.
    // Then instantiate circles and engines and peers for all peers that
    // are receiving a message in updates.
    CFMutableDictionaryRef circle_peer_messages_table = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableDictionaryRef circle_circle_messages_table = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableDictionaryRef circle_retirement_messages_table = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableDictionaryRef ring_update_message_table = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFMutableDictionaryRef debug_info_message_table = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    __block CFMutableDictionaryRef config_message_table = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    
    __block CFDataRef newParameters = NULL;
    __block bool initial_sync = false;
    __block CFStringRef kvs_account_dsid = NULL;
    bool sosIsEnabled = [account sosIsEnabled];
    
    CFDictionaryForEach(updates, ^(const void *key, const void *value) {
        CFStringRef circle_name = NULL;
        CFStringRef ring_name = NULL;
        CFStringRef peer_info_name = NULL;
        CFStringRef from_name = NULL;
        CFStringRef to_name = NULL;
        CFStringRef backup_name = NULL;
        
        require_quiet(isString(key), errOut);
        
        // if SOS is disabled only listen for account change, key parameter and circle changes. and recovery ring and icloud identity ring
        switch (SOSKVSKeyGetKeyTypeAndParse(key, &circle_name, &peer_info_name, &ring_name, &backup_name, &from_name, &to_name)) {
            case kCircleKey:
                CFDictionarySetValue(circle_circle_messages_table, circle_name, value);
                break;
            case kInitialSyncKey:
                if(sosIsEnabled) {
                    initial_sync = true;
                }
                break;
            case kParametersKey:
                if (isData(value)) {
                    newParameters = (CFDataRef) CFRetainSafe(value);
                }
                break;
            case kMessageKey: {
                if(sosIsEnabled) {
                    CFMutableDictionaryRef circle_messages = CFDictionaryEnsureCFDictionaryAndGetCurrentValue(circle_peer_messages_table, circle_name);
                    CFDictionarySetValue(circle_messages, from_name, value);
                }
                break;
            }
            case kRetirementKey: {
                if(sosIsEnabled) {
                    CFMutableDictionaryRef circle_retirements = CFDictionaryEnsureCFDictionaryAndGetCurrentValue(circle_retirement_messages_table, circle_name);
                    CFDictionarySetValue(circle_retirements, from_name, value);
                }
                break;
            }
            case kDSIDKey:
                kvs_account_dsid = NULL;
                if (isData(value)) {
                    kvs_account_dsid = CFStringCreateFromExternalRepresentation(kCFAllocatorDefault, (CFDataRef) value, kCFStringEncodingUTF8);
                } else if (isString(value)) {
                    kvs_account_dsid = CFRetain(value);
                }
                break;
            case kRingKey:
                if(isString(ring_name)) {
                    if(sosIsEnabled || sosDisabledRingException(ring_name)) { // listen for recovery ring and icloud identity ring
                        CFDictionarySetValue(ring_update_message_table, ring_name, value);
                    }
                }
                break;
            case kDebugInfoKey:
                if(sosIsEnabled) {
                    CFDictionarySetValue(debug_info_message_table, peer_info_name, value);
                }
                break;
            case kLastCircleKey:
            case kLastKeyParameterKey:
            case kUnknownKey:
                secnotice("updates", "Unknown key '%@', ignoring", key);
                break;
        }

    errOut:
        CFReleaseNull(circle_name);
        CFReleaseNull(from_name);
        CFReleaseNull(to_name);
        CFReleaseNull(ring_name);
        CFReleaseNull(peer_info_name);
        CFReleaseNull(backup_name);
        
        if (error && *error)
            secerror("Peer message processing error for: %@ -> %@ (%@)", key, value, *error);
    });
    
    
    if (newParameters) {
        CFArrayForEach(SOSGetTransportKeyParameters(), ^(const void *value) {
            CKKeyParameter* tkvs = (__bridge CKKeyParameter*) value;
            CFErrorRef localError = NULL;
            if([[tkvs SOSTransportKeyParameterGetAccount:tkvs] isEqual:account]){
                if(![tkvs SOSTransportKeyParameterHandleKeyParameterChanges:tkvs data:newParameters err:localError])
                    secerror("Transport failed to handle new key parameters: %@", localError);
            }
        });
        CFArrayAppendValue(handledKeys, kSOSKVSKeyParametersKey);
    }
    CFReleaseNull(newParameters);
    
    if(kvs_account_dsid) {
        SOSAccountAssertDSID(txn.account, kvs_account_dsid);
        CFReleaseNull(kvs_account_dsid);
    }
    
    if(initial_sync){
        CFArrayAppendValue(handledKeys, kSOSKVSInitialSyncKey);
    }

    if(CFDictionaryGetCount(debug_info_message_table)) {
        /* check for a newly set circle debug scope */
        CFTypeRef debugScope = CFDictionaryGetValue(debug_info_message_table, kSOSAccountDebugScope);
        if (debugScope) {
            if(isString(debugScope)){
                ApplyScopeListForID(debugScope, kScopeIDCircle);
            }else if(isDictionary(debugScope)){
                ApplyScopeDictionaryForID(debugScope, kScopeIDCircle);
            }
        }
        CFStringRef debugInfoKey = SOSDebugInfoKeyCreateWithTypeName(kSOSAccountDebugScope);
        CFArrayAppendValue(handledKeys, debugInfoKey);
        CFReleaseNull(debugInfoKey);
    }
    
    if(CFDictionaryGetCount(circle_retirement_messages_table)) {
        CFArrayForEach(SOSGetTransportCircles(), ^(const void *value) {
            SOSKVSCircleStorageTransport* tkvs = (__bridge SOSKVSCircleStorageTransport*) value;
            if([[tkvs getAccount] isEqual:account]){
                CFErrorRef localError = NULL;
                CFDictionaryRef handledRetirementKeys = [tkvs handleRetirementMessages:circle_retirement_messages_table err:error];
                if(handledRetirementKeys == NULL){
                    secerror("Transport failed to handle retirement messages: %@", localError);
                } else {
                    CFDictionaryForEach(handledRetirementKeys, ^(const void *key, const void *value) {
                        CFStringRef circle_name = (CFStringRef)key;
                        CFArrayRef handledPeerIDs = (CFArrayRef)value;
                        CFArrayForEach(handledPeerIDs, ^(const void *value) {
                            CFStringRef peer_id = (CFStringRef)value;
                            CFStringRef keyHandled = SOSRetirementKeyCreateWithCircleNameAndPeer(circle_name, peer_id);
                            CFArrayAppendValue(handledKeys, keyHandled);
                            CFReleaseNull(keyHandled);
                        });
                    });
                }
                CFReleaseNull(handledRetirementKeys);
                CFReleaseNull(localError);
            }
        });
    }
    if(CFDictionaryGetCount(circle_peer_messages_table)) {
        CFArrayForEach(SOSGetTransportMessages(), ^(const void *value) {
            SOSMessage* tmsg = (__bridge SOSMessage*) value;
            CFDictionaryRef circleToPeersHandled = NULL;
            CFErrorRef handleMessagesError = NULL;
            CFErrorRef flushError = NULL;

            if(!([([tmsg SOSTransportMessageGetAccount]) isEqual:account])){
                CFReleaseNull(flushError);
                CFReleaseNull(circleToPeersHandled);
                CFReleaseNull(handleMessagesError);
                return;
            }
            circleToPeersHandled = [tmsg SOSTransportMessageHandlePeerMessageReturnsHandledCopy:tmsg peerMessages:circle_peer_messages_table err:&handleMessagesError];
            if(!circleToPeersHandled){
                secnotice("msg", "No messages handled: %@", handleMessagesError);
                CFReleaseNull(flushError);
                CFReleaseNull(circleToPeersHandled);
                CFReleaseNull(handleMessagesError);
                return;
            }
            CFArrayRef handledPeers = asArray(CFDictionaryGetValue(circleToPeersHandled, [tmsg SOSTransportMessageGetCircleName]), NULL);

            if (handledPeers) {
                CFArrayForEach(handledPeers, ^(const void *value) {
                    CFStringRef peerID = asString(value, NULL);
                    if (peerID) {
                        CFStringRef kvsHandledKey = SOSMessageKeyCreateFromPeerToTransport(tmsg, (__bridge CFStringRef) account.peerID, peerID);
                        if (kvsHandledKey) {
                            CFArrayAppendValue(handledKeys, kvsHandledKey);
                        }
                        CFReleaseNull(kvsHandledKey);
                    }
                });
            }

            if(![tmsg SOSTransportMessageFlushChanges:tmsg err:&flushError])
                secnotice("msg", "Flush failed: %@", flushError);

            CFReleaseNull(flushError);
            CFReleaseNull(circleToPeersHandled);
            CFReleaseNull(handleMessagesError);
        });
    }
    if(CFDictionaryGetCount(circle_circle_messages_table)) {
        CFArrayForEach(SOSGetTransportCircles(), ^(const void *value) {
            SOSKVSCircleStorageTransport* tkvs = (__bridge SOSKVSCircleStorageTransport*) value;
            if([[tkvs getAccount] isEqual: account]){
                CFArrayRef handleCircleMessages = [tkvs handleCircleMessagesAndReturnHandledCopy:circle_circle_messages_table err:error];
                CFErrorRef localError = NULL;
                if(handleCircleMessages == NULL){
                    secerror("Transport failed to handle circle messages: %@", localError);
                } else if(CFArrayGetCount(handleCircleMessages) == 0) {
                    if(CFDictionaryGetCount(circle_circle_messages_table) != 0) {
                        secerror("Transport failed to process all circle messages: (%ld/%ld) %@",
                                 CFArrayGetCount(handleCircleMessages),
                                 CFDictionaryGetCount(circle_circle_messages_table), localError);
                    } else {
                        secnotice("circle", "Transport handled no circle messages");
                    }
                } else {
                    CFArrayForEach(handleCircleMessages, ^(const void *value) {
                        CFStringRef keyHandled = SOSCircleKeyCreateWithName((CFStringRef)value, error);
                        CFArrayAppendValue(handledKeys, keyHandled);
                        CFReleaseNull(keyHandled);
                    });
                }

                CFReleaseNull(handleCircleMessages);
                CFReleaseNull(localError);
            }
            
        });
    }
    if(CFDictionaryGetCount(ring_update_message_table)){
        CFArrayForEach(SOSGetTransportCircles(), ^(const void *value) {
            SOSKVSCircleStorageTransport* tkvs = (__bridge SOSKVSCircleStorageTransport*) value;
            if([[tkvs getAccount] isEqual:account]){
                CFErrorRef localError = NULL;
                CFMutableArrayRef handledRingMessages = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);

                CFDictionaryForEach(ring_update_message_table, ^(const void *key, const void *value) {
                    CFDataRef ringData = asData(value, NULL);
                    SOSRingRef ring = SOSRingCreateFromData(error, ringData);

                    if(SOSAccountUpdateRingFromRemote(account, ring, error)){
                        CFArrayAppendValue(handledRingMessages, key);
                    }
                    CFReleaseNull(ring);
                });
                if(CFArrayGetCount(handledRingMessages) == 0){
                    secerror("Transport failed to handle ring messages: %@", localError);
                } else {
                    CFArrayForEach(handledRingMessages, ^(const void *value) {
                        CFStringRef ring_name = (CFStringRef)value;
                        CFStringRef keyHandled = SOSRingKeyCreateWithRingName(ring_name);
                        CFArrayAppendValue(handledKeys, keyHandled);
                        CFReleaseNull(keyHandled);
                    });
                }
                CFReleaseNull(handledRingMessages);
                CFReleaseNull(localError);
            }
        });
    }

    CFReleaseNull(circle_retirement_messages_table);
    CFReleaseNull(circle_circle_messages_table);
    CFReleaseNull(circle_peer_messages_table);
    CFReleaseNull(debug_info_message_table);
    CFReleaseNull(ring_update_message_table);
    CFReleaseNull(debug_info_message_table);
    CFReleaseNull(config_message_table);
    showWhatWasHandled(updates, handledKeys);
    
    return handledKeys;
}

