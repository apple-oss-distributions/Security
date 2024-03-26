/*
 * Copyright (c) 2013-2014 Apple Inc. All Rights Reserved.
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

#include "SOSAccountPriv.h"
#include "SOSAccount.h"
#include "keychain/SecureObjectSync/SOSPeerInfoCollections.h"
#include "keychain/SecureObjectSync/SOSTransportMessage.h"
#include "keychain/SecureObjectSync/SOSPeerInfoV2.h"
#import "keychain/SecureObjectSync/SOSAccountTrust.h"
#include "keychain/SecureObjectSync/SOSAccountTrustClassic+Circle.h"

bool SOSAccountIsMyPeerActive(SOSAccount* account, CFErrorRef* error) {
    SOSFullPeerInfoRef identity = NULL;
    SOSCircleRef circle = NULL;

    SOSAccountTrustClassic *trust = account.trust;
    identity = trust.fullPeerInfo;
    circle = trust.trustedCircle;

    SOSPeerInfoRef me = SOSFullPeerInfoGetPeerInfo(identity);
    return me ? SOSCircleHasActivePeer(circle, me, error) : false;
}

//
// MARK: Peer Querying
//


static void sosArrayAppendPeerCopy(CFMutableArrayRef appendPeersTo, SOSPeerInfoRef peer) {
    SOSPeerInfoRef peerInfo = SOSPeerInfoCreateCopy(kCFAllocatorDefault, peer, NULL);
    CFArrayAppendValue(appendPeersTo, peerInfo);
    CFRelease(peerInfo);
}

static CFArrayRef SOSAccountCopySortedPeerArray(SOSAccount* account,
                                                CFErrorRef *error,
                                                void (^action)(SOSCircleRef circle, CFMutableArrayRef appendPeersTo)) {
    if (!SOSAccountHasPublicKey(account, error))
        return NULL;
    
    CFMutableArrayRef peers = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    SOSCircleRef circle = NULL;

    SOSAccountTrustClassic *trust = account.trust;
    circle = trust.trustedCircle;
    action(circle, peers);

    CFArrayOfSOSPeerInfosSortByID(peers);

    return peers;
}


CFArrayRef SOSAccountCopyNotValidPeers(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachPeer(circle, ^(SOSPeerInfoRef peer) {
            if(!SOSPeerInfoApplicationVerify(peer, account.accountKey, NULL)) {
                sosArrayAppendPeerCopy(appendPeersTo, peer);
            }
        });
    });
}


CFArrayRef SOSAccountCopyValidPeers(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachPeer(circle, ^(SOSPeerInfoRef peer) {
            if(SOSPeerInfoApplicationVerify(peer, account.accountKey, NULL)) {
                sosArrayAppendPeerCopy(appendPeersTo, peer);
            }
        });
    });
}



CFArrayRef SOSAccountCopyPeersToListenTo(SOSAccount* account, CFErrorRef *error) {
    SOSFullPeerInfoRef identity = NULL;

    SOSAccountTrustClassic *trust = account.trust;
    identity = trust.fullPeerInfo;
    SOSPeerInfoRef myPeerInfo = SOSFullPeerInfoGetPeerInfo(identity);
    CFStringRef myID = myPeerInfo ? SOSPeerInfoGetPeerID(myPeerInfo) : NULL;
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachPeer(circle, ^(SOSPeerInfoRef peer) {
            if(!CFEqualSafe(myID, SOSPeerInfoGetPeerID(peer)) &&
               SOSPeerInfoApplicationVerify(peer, account.accountKey, NULL) &&
               !SOSPeerInfoIsRetirementTicket(peer)) {
                CFArrayAppendValue(appendPeersTo, peer);
            }
        });
    });
}

CFArrayRef SOSAccountCopyRetired(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachRetiredPeer(circle, ^(SOSPeerInfoRef peer) {
            sosArrayAppendPeerCopy(appendPeersTo, peer);
        });
    });
}

CFArrayRef SOSAccountCopyViewUnawareIncludingInvalid(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachPeer(circle, ^(SOSPeerInfoRef peer) {
            if (!SOSPeerInfoVersionHasV2Data(peer)) {
                sosArrayAppendPeerCopy(appendPeersTo, peer);
            }        });
    });
}

CFArrayRef SOSAccountCopyViewUnaware(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachPeer(circle, ^(SOSPeerInfoRef peer) {
            if (!SOSPeerInfoVersionHasV2Data(peer) && SOSPeerInfoApplicationVerify(peer, account.accountKey, NULL)) {
                sosArrayAppendPeerCopy(appendPeersTo, peer);
            }        });
    });
}

CFArrayRef SOSAccountCopyApplicants(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachApplicant(circle, ^(SOSPeerInfoRef peer) {
            sosArrayAppendPeerCopy(appendPeersTo, peer);
        });
    });
}

CFArrayRef SOSAccountCopyPeers(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachPeer(circle, ^(SOSPeerInfoRef peer) {
            sosArrayAppendPeerCopy(appendPeersTo, peer);
        });
    });
}

CFArrayRef SOSAccountCopyActivePeers(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachActivePeer(circle, ^(SOSPeerInfoRef peer) {
            sosArrayAppendPeerCopy(appendPeersTo, peer);
        });
    });
}

CFArrayRef CF_RETURNS_RETAINED SOSAccountCopyActiveValidPeers(SOSAccount* account, CFErrorRef *error) {
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleForEachActiveValidPeer(circle, account.accountKey, ^(SOSPeerInfoRef peer) {
            sosArrayAppendPeerCopy(appendPeersTo, peer);
        });
    });
}

CFArrayRef SOSAccountCopyConcurringPeers(SOSAccount* account, CFErrorRef *error)
{
    return SOSAccountCopySortedPeerArray(account, error, ^(SOSCircleRef circle, CFMutableArrayRef appendPeersTo) {
        SOSCircleAppendConcurringPeers(circle, appendPeersTo, NULL);
    });
}

SOSPeerInfoRef SOSAccountCopyPeerWithID(SOSAccount* account, CFStringRef peerid, CFErrorRef *error) {
    SOSCircleRef circle = NULL;

    SOSAccountTrustClassic *trust = account.trust;
    circle = trust.trustedCircle;
    if(!circle) return NULL;
    return SOSCircleCopyPeerWithID(circle, peerid, error);
}

CFBooleanRef SOSAccountPeersHaveViewsEnabled(SOSAccount* account, CFArrayRef viewNames, CFErrorRef *error) {
    CFBooleanRef result = NULL;
    CFMutableSetRef viewsRemaining = NULL;
    CFSetRef viewsToLookFor = NULL;

    if(![account isInCircle:error]) {
        CFReleaseNull(viewsToLookFor);
        CFReleaseNull(viewsRemaining);
        return result;
    }

    viewsToLookFor = CFSetCreateCopyOfArrayForCFTypes(viewNames);
    viewsRemaining = CFSetCreateMutableCopy(kCFAllocatorDefault, 0, viewsToLookFor);
    CFReleaseNull(viewsToLookFor);

    SOSAccountForEachCirclePeerExceptMe(account, ^(SOSPeerInfoRef peer) {
        if (SOSPeerInfoApplicationVerify(peer, account.accountKey, NULL)) {
            CFSetRef peerViews = SOSPeerInfoCopyEnabledViews(peer);
            CFSetSubtract(viewsRemaining, peerViews);
            CFReleaseNull(peerViews);
        }
    });

    result = CFSetIsEmpty(viewsRemaining) ? kCFBooleanTrue : kCFBooleanFalse;

    CFReleaseNull(viewsToLookFor);
    CFReleaseNull(viewsRemaining);

    return result;
}

bool SOSAccountRemoveV0Clients(SOSAccount *account, CFErrorRef *error) {
    CFErrorRef localError = NULL;
    
    CFArrayRef v0Peers = SOSAccountCopyViewUnawareIncludingInvalid(account, &localError);
    if (error && localError) {
        CFTransferRetained(*error, localError);
    }
    
    if (v0Peers == NULL || CFArrayGetCount(v0Peers) == 0) {
        CFReleaseNull(localError);
        CFReleaseNull(v0Peers);
        return true;
    }
    
    bool result = SOSAccountRemovePeersFromCircle(account, v0Peers, &localError);
    if (error && localError) {
        CFTransferRetained(*error, localError);
    }
    
    CFReleaseNull(localError);
    CFReleaseNull(v0Peers);

    return result;
}
