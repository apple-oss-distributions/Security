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




#include <Security/SecBase.h>
#include <Security/SecItem.h>

#include <CoreFoundation/CFDictionary.h>

#include "keychain/SecureObjectSync/SOSAccount.h"
#include <Security/SecureObjectSync/SOSCloudCircle.h>
#include "keychain/SecureObjectSync/SOSInternal.h"
#include "keychain/SecureObjectSync/SOSUserKeygen.h"
#include "keychain/SecureObjectSync/SOSKVSKeys.h"
#include "keychain/SecureObjectSync/SOSTransport.h"
#include "keychain/SecureObjectSync/SOSAccountTrustClassic+Retirement.h"
#include <stdlib.h>
#include <unistd.h>

#include "secd_regressions.h"
#include "SOSTestDataSource.h"

#include "SOSRegressionUtilities.h"
#include <utilities/SecCFWrappers.h>
#include <Security/SecKeyPriv.h>

#include "keychain/securityd/SOSCloudCircleServer.h"

#include "SOSAccountTesting.h"

#include "SecdTestKeychainUtilities.h"

#if SOS_ENABLED

static void tests(void)
{
    CFErrorRef error = NULL;
    CFDataRef cfpassword = CFDataCreate(NULL, (uint8_t *) "FooFooFoo", 10);
    CFStringRef cfaccount = CFSTR("test@test.org");
    CFStringRef circle_name = CFSTR("TestSource");
    
    CFMutableDictionaryRef changes = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);

    SOSAccount* alice_account = CreateAccountForLocalChanges(CFSTR("Alice"), circle_name);
    SOSAccount* bob_account = CreateAccountForLocalChanges(CFSTR("Bob"), circle_name);
    SOSAccount* carole_account = CreateAccountForLocalChanges(CFSTR("Carole"), circle_name);
    
    ok(SOSAccountAssertUserCredentialsAndUpdate(bob_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    
    // Bob wins writing at this point, feed the changes back to alice.
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 1, "updates");

    ok(SOSAccountAssertUserCredentialsAndUpdate(alice_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);
    
    ok(SOSAccountAssertUserCredentialsAndUpdate(carole_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);
    ok(SOSAccountResetToOffering_wTxn(alice_account, &error), "Reset to offering (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 2, "updates");

    ok(SOSAccountJoinCircles_wTxn(bob_account, &error), "Bob Applies (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 2, "updates");

    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);
        
        ok(applicants && CFArrayGetCount(applicants) == 1, "See one applicant %@ (%@)", applicants, error);
        ok(SOSAccountAcceptApplicants(alice_account, applicants, &error), "Alice accepts (%@)", error);
        CFReleaseNull(error);
        CFReleaseNull(applicants);
    }
    
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 3, "updates");

    accounts_agree("bob&alice pair", bob_account, alice_account);
    
    CFArrayRef peers = SOSAccountCopyPeers(alice_account, &error);
    ok(peers && CFArrayGetCount(peers) == 2, "See two peers %@ (%@)", peers, error);
    CFReleaseNull(peers);
    
    ok([alice_account.trust leaveCircle:alice_account err:&error], "Alice Leaves (%@)", error);
    CFReleaseNull(error);
    CFReleaseNull(cfpassword);
    
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 2, "updates");

    accounts_agree("Alice bails", bob_account, alice_account);
    accounts_agree("Alice bails", bob_account, carole_account);
    
    [bob_account.trust cleanupRetirementTickets:bob_account circle:bob_account.trust.trustedCircle time:0 err:&error];

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 1, "updates");
    
    ok(SOSAccountJoinCircles_wTxn(carole_account, &error), "Carole Applies (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 2, "updates");

    
    {
        CFArrayRef applicants = SOSAccountCopyApplicants(bob_account, &error);
        
        ok(applicants && CFArrayGetCount(applicants) == 1, "See one applicant %@ (%@)", applicants, error);
        ok(SOSAccountAcceptApplicants(bob_account, applicants, &error), "Bob accepts Carole (%@)", error);
        CFReleaseNull(error);
        CFReleaseNull(applicants);
    }

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 3, "updates");

    accounts_agree("Carole joins", bob_account, carole_account);
    
    [bob_account.trust cleanupRetirementTickets:bob_account circle:bob_account.trust.trustedCircle time:0 err:&error];

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, NULL), 1, "updates");

    is(countPeers(bob_account), 2, "Active peers after forced cleanup");
    is(countActivePeers(bob_account), 3, "Inactive peers after forced cleanup");

    alice_account = nil;
    bob_account = nil;
    SOSTestCleanup();
}

#define AVPEER1 CFSTR("aaaaaaaa")
#define AVPEER2 CFSTR("bbbbbbbb")
#define RTPEER1 CFSTR("R1R1R1R1")
#define RTPEER2 CFSTR("R2R2R2R2")
#define INVPEER1 CFSTR("I1I1I1I1I1")
#define INVPEER2 CFSTR("I2I2I2I2I2")
#define CIRCLENAME CFSTR("ak")
static void tests2(void)
{
    CFMutableSetRef peerIDs = CFSetCreateMutableForCFTypes(kCFAllocatorDefault);
    CFSetAddValue(peerIDs, AVPEER1);
    CFSetAddValue(peerIDs, AVPEER2);
    CFSetAddValue(peerIDs, RTPEER1);
    
    CFMutableSetRef retiredPeerIDs = CFSetCreateMutableForCFTypes(kCFAllocatorDefault);
    CFSetAddValue(retiredPeerIDs, RTPEER1);  // Assuming RTPEER1 is actually in the circle  RTPEER2 isn't
    
    CFMutableArrayRef allPeerIDs = CFArrayCreateMutableForCFTypesWith(kCFAllocatorDefault,
            AVPEER1, AVPEER2, RTPEER1, RTPEER2, INVPEER1, INVPEER2, nil);
    
    CFMutableDictionaryRef keysAndValues = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFArrayForEach(allPeerIDs, ^(const void *value1) {
        CFArrayForEach(allPeerIDs, ^(const void *value2) {
            if(!CFEqual(value1, value2)) {
                CFStringRef key = SOSMessageKeyCreateWithCircleNameAndPeerNames(CIRCLENAME, value1, value2);
                CFDictionaryAddValue(keysAndValues, key, CFSTR("theData"));
                CFReleaseNull(key);
            }
        });
    });
    CFStringRef retirementKey = SOSRetirementKeyCreateWithCircleNameAndPeer(CIRCLENAME, RTPEER1);
    CFDictionaryAddValue(keysAndValues, retirementKey, CFSTR("blank"));
    CFReleaseNull(retirementKey);
    retirementKey = SOSRetirementKeyCreateWithCircleNameAndPeer(CIRCLENAME, RTPEER2);
    CFDictionaryAddValue(keysAndValues, retirementKey, CFSTR("blank"));
    CFReleaseNull(retirementKey);

    NSMutableArray *  toDelete = SOSAccountScanForDeletions(keysAndValues, peerIDs, retiredPeerIDs);
    
    // Given the mix of records above there should be 25 recommended deletions.
    // 1 retirement key
    // all message keys with either retirement peer or the additional invalid peers
    ok(toDelete != NULL && [toDelete count] == 25, "%d ToDelete = %@", (int) [toDelete count], toDelete);
}

#endif

int secd_59_account_cleanup(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(92);
    enableSOSCompatibilityForTests();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    tests();
    tests2();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
