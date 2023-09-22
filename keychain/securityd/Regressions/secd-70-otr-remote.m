/*
 * Copyright (c) 2014 Apple Inc. All Rights Reserved.
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


#include <stdio.h>

#include "secd_regressions.h"

#include <CoreFoundation/CFData.h>
#include <Security/SecOTRSession.h>
#include <Security/SecOTRIdentityPriv.h>
#include <Security/SecInternal.h>
#include <Security/SecBasePriv.h>
#include <Security/SecKeyPriv.h>

#include <Security/SecureObjectSync/SOSPeerInfo.h>
#include "keychain/SecureObjectSync/SOSCircle.h"
#include <Security/SecureObjectSync/SOSCloudCircle.h>
#include "keychain/SecureObjectSync/SOSInternal.h"
#include "keychain/SecureObjectSync/SOSUserKeygen.h"
#include "keychain/SecureObjectSync/SOSTransport.h"

#include "SOSCircle_regressions.h"
#include "SOSRegressionUtilities.h"
#include "SOSTestDataSource.h"
#include "SecOTRRemote.h"
#include "SOSAccount.h"
#include "SOSAccountTesting.h"

#include "SecdTestKeychainUtilities.h"
#if SOS_ENABLED


static void RegressionsLogError(CFErrorRef error) {
    if (error == NULL) {
        return;
    }
    CFDictionaryRef tempDictionary = CFErrorCopyUserInfo(error);
    CFIndex errorCode = CFErrorGetCode(error);
    CFStringRef errorDomain = CFErrorGetDomain(error);
    CFStringRef errorString = CFDictionaryGetValue(tempDictionary, kCFErrorDescriptionKey);
    CFErrorRef previousError = (CFErrorRef)CFDictionaryGetValue(tempDictionary, kCFErrorUnderlyingErrorKey);
    if (previousError != NULL) {
        RegressionsLogError(previousError);
    }
    char errorDomainStr[1024];
    char errorStringStr[1024];
    
    CFStringGetCString(errorDomain, errorDomainStr, 1024, kCFStringEncodingUTF8);
    CFStringGetCString(errorString, errorStringStr, 1024, kCFStringEncodingUTF8);
    printf("OTR: %s (%ld) -- %s\n", errorDomainStr, errorCode, errorStringStr);
    CFReleaseSafe(tempDictionary);
}

static int kTestTestCount = 11;
static void tests(void)
{
    NSError* ns_testError = nil;
    __block CFErrorRef testError = NULL;
    
    CFDataRef cfpassword = CFDataCreate(NULL, (uint8_t *) "FooFooFoo", 10);
    
    CFStringRef circleName = CFSTR("Woot Circle");
    
    /* DataSource */
    SOSDataSourceRef aliceDs = SOSTestDataSourceCreate();
    SOSDataSourceRef bobDs = SOSTestDataSourceCreate();
    
    SOSDataSourceFactoryRef aliceDsf = SOSTestDataSourceFactoryCreate();
    SOSTestDataSourceFactorySetDataSource(aliceDsf, circleName, aliceDs);
    
    SOSDataSourceFactoryRef bobDsf = SOSTestDataSourceFactoryCreate();
    SOSTestDataSourceFactorySetDataSource(bobDsf, circleName, bobDs);
    
    CFDictionaryRef alice_gestalt = SOSCreatePeerGestaltFromName(CFSTR("Alice Device"));
    CFDictionaryRef bob_gestalt = SOSCreatePeerGestaltFromName(CFSTR("Bob Device"));
    
    SOSAccount* alice_account = SOSAccountCreate(kCFAllocatorDefault, alice_gestalt, aliceDsf);
    SOSAccount* bob_account = SOSAccountCreate(kCFAllocatorDefault, bob_gestalt, bobDsf);
    
    SOSAccountAssertUserCredentialsAndUpdate(alice_account, CFSTR("alice"), cfpassword, &testError);
    SOSAccountAssertUserCredentialsAndUpdate(bob_account, CFSTR("bob"), cfpassword, &testError);
    
    CFReleaseNull(cfpassword);
    
    SOSAccountJoinCircles_wTxn(alice_account, &testError);
    SOSAccountJoinCircles_wTxn(bob_account, &testError);
    
    NSData* alice_account_data = [alice_account encodedData:&ns_testError];
    NSData* bob_account_data = [bob_account encodedData:&ns_testError];
    
    CFArrayRef alice_peers = SOSAccountCopyPeers(alice_account, &testError);
    CFArrayRef bob_peers = SOSAccountCopyPeers(bob_account, &testError);
    
    SOSPeerInfoRef alice_peer_info = (SOSPeerInfoRef)CFArrayGetValueAtIndex(alice_peers, 0);
    SOSPeerInfoRef bob_peer_info = (SOSPeerInfoRef)CFArrayGetValueAtIndex(bob_peers, 0);
    
    CFStringRef alice_peer_id = SOSPeerInfoGetPeerID(alice_peer_info);
    CFStringRef bob_peer_id = SOSPeerInfoGetPeerID(bob_peer_info);
    
    CFDataRef alice_peer_external_form = CFStringCreateExternalRepresentation(kCFAllocatorDefault, alice_peer_id, kCFStringEncodingUTF8, '?');
    CFDataRef bob_peer_external_form = CFStringCreateExternalRepresentation(kCFAllocatorDefault, bob_peer_id, kCFStringEncodingUTF8, '?');
    
    bool aliceReady = false;
    bool bobReady = false;
    
    CFDataRef aliceSideSession = SecOTRSessionCreateRemote_internal((__bridge CFDataRef) bob_account_data, bob_peer_external_form, (__bridge CFDataRef) alice_account_data, &testError);
    RegressionsLogError(testError);
    CFReleaseNull(testError);
    
    ok(aliceSideSession != NULL, "Make Alice side remote session");
    
    CFDataRef bobSideSession = SecOTRSessionCreateRemote_internal((__bridge CFDataRef) alice_account_data, alice_peer_external_form, (__bridge CFDataRef) bob_account_data, &testError);
    RegressionsLogError(testError);
    CFReleaseNull(testError);
    
    ok(bobSideSession != NULL, "Make Bob side remote session");
    
    CFDataRef aliceSideSessionResult = NULL;
    CFDataRef bobSideSessionResult = NULL;
    CFDataRef aliceToBob = NULL;
    CFDataRef bobToAlice = NULL;
    
    do {
        bool aliceStatus = SecOTRSessionProcessPacketRemote(aliceSideSession, bobToAlice, &aliceSideSessionResult, &aliceToBob, &aliceReady, &testError);
        ok (aliceStatus, "Alice sent packet OK");
        RegressionsLogError(testError);
        CFReleaseNull(testError);
        CFReleaseSafe(aliceSideSession);
        aliceSideSession = aliceSideSessionResult;
        
        if (aliceReady) {
            break;
        }
        
        bool bobStatus = SecOTRSessionProcessPacketRemote(bobSideSession, aliceToBob, &bobSideSessionResult, &bobToAlice, &bobReady, &testError);
        ok (bobStatus, "Bob sent packet OK");
        RegressionsLogError(testError);
        CFReleaseNull(testError);
        CFReleaseSafe(bobSideSession);
        bobSideSession = bobSideSessionResult;
    } while (1);
    
    ok(bobReady, "Bob finished negotiating at the same time as Alice.");
    
    CFReleaseNull(aliceSideSession);
    CFReleaseNull(bobSideSession);
    SOSDataSourceRelease(aliceDs, NULL);
    SOSDataSourceFactoryRelease(aliceDsf);

    SOSDataSourceRelease(bobDs, NULL);
    SOSDataSourceFactoryRelease(bobDsf);

    SecOTRFIPurgeAllFromKeychain(&testError);
    RegressionsLogError(testError);
    CFReleaseNull(bob_peer_external_form);
    CFReleaseNull(alice_peer_external_form);
    CFReleaseNull(alice_peers);
    CFReleaseNull(bob_peers);
    CFReleaseNull(aliceSideSession);
    CFReleaseNull(bobSideSession);
    CFReleaseNull(testError);
}
#endif

int secd_70_otr_remote(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(kTestTestCount);
    enableSOSCompatibilityForTests();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    tests();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
