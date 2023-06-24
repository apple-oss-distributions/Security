/*
 * Copyright (c) 2012-2014 Apple Inc. All Rights Reserved.
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


/*
 * SOSCloudKeychainClient.h -  Implementation of the transport layer from CKBridge to SOSAccount/SOSCircle
 */

/*!
    @header SOSCloudKeychainClient
    The functions provided in SOSCloudTransport.h provide an interface
    from CKBridge to SOSAccount/SOSCircle
 */

#ifndef _SOSCLOUDKEYCHAINCLIENT_H_
#define _SOSCLOUDKEYCHAINCLIENT_H_

#include <CoreFoundation/CFArray.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFError.h>
#include <dispatch/dispatch.h>

__BEGIN_DECLS


// MARK: ---------- SOSCloudTransport ----------

enum
{
    kSOSObjectNotFoundError = 1,
    kSOSObjectCantBeConvertedToXPCObject,
    kSOSOUnexpectedConnectionEvent,
    kSOSOXPCErrorEvent,
    kSOSOUnexpectedXPCEvent,
    kSOSConnectionNotOpen,
    kSOSNoServerReply,
    kSOSMessageInvalid,
    kSOSMessageNotSupported,
};

typedef CFArrayRef (^CloudItemsChangedBlock)(CFDictionaryRef values);
typedef void (^CloudKeychainReplyBlock)(CFDictionaryRef returnedValues, CFErrorRef error);

/* SOSCloudTransport protocol.  */
typedef struct SOSCloudTransport *SOSCloudTransportRef;
struct SOSCloudTransport
{
    void (*put)(SOSCloudTransportRef transport, CFDictionaryRef valuesToPut, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*updateKeys)(SOSCloudTransportRef transport, CFDictionaryRef keys, CFStringRef accountUUID, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

    void (*getDeviceID)(SOSCloudTransportRef transport, CloudKeychainReplyBlock replyBlock);

    // Debug calls
    void (*get)(SOSCloudTransportRef transport, CFArrayRef keysToGet, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*getAll)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*synchronize)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*synchronizeAndWait)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

    void (*clearAll)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*removeObjectForKey)(SOSCloudTransportRef transport, CFStringRef keyToRemove, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

    bool (*hasPendingKey)(SOSCloudTransportRef transport, CFStringRef keyName, CFErrorRef* error);

    void (*requestSyncWithPeers)(SOSCloudTransportRef transport, CFArrayRef /* CFStringRef */ peers, CFArrayRef /* CFStringRef */ backupPeers, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

    void (*requestEnsurePeerRegistration)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*requestPerfCounters)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*flush)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    const void *itemsChangedBlock;
    void (*removeKeys)(SOSCloudTransportRef transport, CFArrayRef keys, CFStringRef accountUUID, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
    void (*counters)(SOSCloudTransportRef transport, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

};

void SOSCloudKeychainUpdateKeys(CFDictionaryRef keys, CFStringRef accountUUID, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

void SOSCloudKeychainPutObjectsInCloud(CFDictionaryRef objects, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

void SOSCloudKeychainSetItemsChangedBlock(CloudItemsChangedBlock itemsChangedBlock);

CF_RETURNS_RETAINED CFArrayRef SOSCloudKeychainHandleUpdateMessage(CFDictionaryRef updates);
void SOSCloudKeychainSynchronizeAndWait(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

// Debug only?

void SOSCloudKeychainGetObjectsFromCloud(CFArrayRef keysToGet, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
void SOSCloudKeychainSynchronize(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
void SOSCloudKeychainClearAll(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
void SOSCloudKeychainGetAllObjectsFromCloud(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
bool SOSCloudKeychainHasPendingKey(CFStringRef keyName, CFErrorRef* error);

void SOSCloudKeychainRequestSyncWithPeers(CFArrayRef /* CFStringRef */ peers, CFArrayRef /* CFStringRef */ backupPeers, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

void SOSCloudKeychainRequestEnsurePeerRegistration(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
void SOSCloudKeychainRequestPerfCounters(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

void SOSCloudKeychainFlush(dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);
CFDictionaryRef SOSCloudCopyKVSState(void);
void SOSCloudKeychainRemoveKeys(CFArrayRef keys, CFStringRef accountUUID, dispatch_queue_t processQueue, CloudKeychainReplyBlock replyBlock);

// For unit tests
void
SOSCloudTransportSetDefaultTransport(SOSCloudTransportRef transport);

__END_DECLS

#endif /* !_SOSCLOUDKEYCHAINCLIENT_H_ */

