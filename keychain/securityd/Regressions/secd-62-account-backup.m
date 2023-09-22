
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




#include <Security/SecBase.h>
#include <Security/SecItem.h>

#include <CoreFoundation/CFDictionary.h>

#include "keychain/SecureObjectSync/SOSAccount.h"
#include <Security/SecureObjectSync/SOSCloudCircle.h>
#include "keychain/SecureObjectSync/SOSInternal.h"
#include "keychain/SecureObjectSync/SOSUserKeygen.h"
#include "keychain/SecureObjectSync/SOSTransport.h"
#include <Security/SecureObjectSync/SOSViews.h>
#include <Security/SecureObjectSync/SOSTypes.h>

#import "keychain/SecureObjectSync/SOSAccountTrustClassic.h"
#import "keychain/SecureObjectSync/SOSAccountTrustClassic+Expansion.h"

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

static CFDataRef CopyBackupKeyForString(CFStringRef string, CFErrorRef *error)
{
    __block CFDataRef result = NULL;
    CFStringPerformWithUTF8CFData(string, ^(CFDataRef stringAsData) {
        result = SOSCopyDeviceBackupPublicKey(stringAsData, error);
    });
    return result;
}

static void tests(void)
{
    __block CFErrorRef error = NULL;
    CFDataRef cfpassword = CFDataCreate(NULL, (uint8_t *) "FooFooFoo", 10);
    CFStringRef cfaccount = CFSTR("test@test.org");


    CFMutableDictionaryRef changes = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    SOSAccount* alice_account = CreateAccountForLocalChanges(CFSTR("Alice"), CFSTR("TestSource"));
    SOSAccount* bob_account = CreateAccountForLocalChanges(CFSTR("Bob"), CFSTR("TestSource"));

    CFDataRef alice_backup_key = CopyBackupKeyForString(CFSTR("Alice Backup Entropy"), &error);
    CFDataRef bob_backup_key = CopyBackupKeyForString(CFSTR("Bob Backup Entropy"), &error);

    ok(SOSAccountAssertUserCredentialsAndUpdate(alice_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountResetToOffering_wTxn(alice_account, &error), "Reset to offering (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 1, "updates");

    ok(SOSAccountAssertUserCredentialsAndUpdate(bob_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 1, "updates");

    ok(SOSAccountJoinCircles_wTxn(bob_account, &error), "Bob Applies (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, "updates");

    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);

        ok(applicants && CFArrayGetCount(applicants) == 1, "See one applicant %@ (%@)", applicants, error);
        ok(SOSAccountAcceptApplicants(alice_account, applicants, &error), "Alice accepts (%@)", error);
        CFReleaseNull(error);
        CFReleaseNull(applicants);
    }

    isInRange(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 1, 3, "updates");
    
    CFArrayRef peers = SOSAccountCopyPeers(alice_account, &error);
    ok(peers && CFArrayGetCount(peers) == 2, "See two peers %@ (%@)", peers, error);
    CFReleaseNull(peers);

    is([alice_account.trust updateView:alice_account name:kTestView1 code:kSOSCCViewEnable err:&error], kSOSCCViewMember, "Enable view (%@)", error);
    CFReleaseNull(error);

    ok([alice_account.trust checkForRings:&error], "Alice_account is good");
    CFReleaseNull(error);

    is([bob_account.trust updateView:bob_account name:kTestView1 code:kSOSCCViewEnable err:&error], kSOSCCViewMember, "Enable view (%@)", error);
    CFReleaseNull(error);

    ok([bob_account.trust checkForRings:&error], "Bob_account is good");
    CFReleaseNull(error);

    ok(SOSAccountSetBackupPublicKey_wTxn(alice_account, alice_backup_key, &error), "Set backup public key, alice (%@)", error);
    CFReleaseNull(error);

    ok([alice_account.trust checkForRings:&error], "Alice_account is good");
    CFReleaseNull(error);

    ok(SOSAccountSetBackupPublicKey_wTxn(bob_account, bob_backup_key, &error), "Set backup public key, bob (%@)", error);
    CFReleaseNull(error);

    ok([bob_account.trust checkForRings:&error], "Alice_account is good");
    CFReleaseNull(error);

    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kTestView1), "Is alice's key in backup before sync?");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kSOSViewiCloudIdentity), "Is alice's key in backup before sync?");

    ok([alice_account.trust checkForRings:&error], "Alice_account is good");
    CFReleaseNull(error);

    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kTestView1), "Is bob in the backup after sync? - 1");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kSOSViewiCloudIdentity), "Is bob in the backup after sync? - 1");

    ok([bob_account.trust checkForRings:&error], "Alice_account is good");
    CFReleaseNull(error);

    isInRange(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, 5, "updates");


    ok([alice_account.trust checkForRings:&error], "Alice_account is good");
    CFReleaseNull(error);

    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kTestView1), "Is alice in backup after sync?");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kSOSViewiCloudIdentity), "Is alice in backup after sync?");

    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kTestView1), "IS bob in the backup after sync");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kSOSViewiCloudIdentity), "IS bob in the backup after sync");

    //
    //Bob leaves the circle
    //
    ok([bob_account.trust leaveCircle:bob_account err:&error], "Bob Leaves (%@)", error);
    CFReleaseNull(error);
    
    //Alice should kick Bob out of the backup!
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, "updates");
    
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kTestView1), "Bob left the circle, Alice is not in the backup");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kSOSViewiCloudIdentity), "Bob left the circle, Alice is not in the backup");

    ok(testAccountPersistence(alice_account), "Test Account->DER->Account Equivalence");

    SOSAccountTrustClassic *bobTrust = bob_account.trust;
    ok(!SOSAccountIsPeerInBackupAndCurrentInView(alice_account, bobTrust.peerInfo, kTestView1), "Bob is still in the backup!");
    ok(!SOSAccountIsPeerInBackupAndCurrentInView(alice_account, bobTrust.peerInfo, kSOSViewiCloudIdentity), "Bob is still in the backup!");

    //Bob gets back into the circle
    ok(SOSAccountJoinCircles_wTxn(bob_account, &error));
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, "updates");
    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);
        
        ok(applicants && CFArrayGetCount(applicants) == 1, "See one applicant %@ (%@)", applicants, error);
        ok(SOSAccountAcceptApplicants(alice_account, applicants, &error), "Alice accepts (%@)", error);
        CFReleaseNull(error);
        CFReleaseNull(applicants);
    }
    
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 3, "updates");

    
    //enables view
    is([bob_account.trust updateView:bob_account name:kTestView1 code:kSOSCCViewEnable err:&error], kSOSCCViewMember, "Enable view (%@)", error);
    CFReleaseNull(error);

    ok(!SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kTestView1), "Bob isn't in the backup yet");

    ok(SOSAccountSetBackupPublicKey_wTxn(bob_account, bob_backup_key, &error), "Set backup public key, bob (%@)", error);

    isInRange(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, 5, "updates");

    //
    //removing backup key for bob account
    //
    
    ok(SOSAccountRemoveBackupPublickey_wTxn(bob_account, &error), "Removing Bob's backup key (%@)", error);
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, "updates");

    ok(!SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kTestView1), "Bob's backup key is in the backup - should not be so!");
    ok(!SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kSOSViewiCloudIdentity), "Bob's backup key is in the backup - should not be so!");
    ok(!SOSAccountIsPeerInBackupAndCurrentInView(alice_account, bobTrust.peerInfo, kTestView1), "Bob is up to date in the backup!");
    ok(!SOSAccountIsPeerInBackupAndCurrentInView(alice_account, bobTrust.peerInfo, kSOSViewiCloudIdentity), "Bob is up to date in the backup!");

    //
    // Setting new backup public key for Bob
    //
    
    ok(SOSAccountSetBackupPublicKey_wTxn(bob_account, bob_backup_key, &error), "Set backup public key, bob (%@)", error);
    CFReleaseNull(error);

    is([bob_account.trust updateView:bob_account name:kTestView1 code:kSOSCCViewEnable err:&error], kSOSCCViewMember, "Enable view (%@)", error);
    ok(SOSAccountNewBKSBForView(bob_account, kTestView1, &error), "Setting new backup public key for bob account failed: (%@)", error);

    //bob is in his own backup
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kTestView1), "Bob's backup key is not in the backup");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kSOSViewiCloudIdentity), "Bob's backup key is not in the backup");
    //alice does not have bob in her backup
    ok(!SOSAccountIsPeerInBackupAndCurrentInView(alice_account, bobTrust.peerInfo, kTestView1), "Bob is up to date in the backup - should not be so!");
    ok(!SOSAccountIsPeerInBackupAndCurrentInView(alice_account, bobTrust.peerInfo, kSOSViewiCloudIdentity), "Bob is up to date in the backup - should not be so!");

    isInRange(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 1, 5, "updates");
    
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kTestView1), "Bob's backup key should be in the backup");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(bob_account, kSOSViewiCloudIdentity), "Bob's backup key should be in the backup");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kTestView1), "Alice is in the backup");
    ok(SOSAccountIsMyPeerInBackupAndCurrentInView(alice_account, kSOSViewiCloudIdentity), "Alice is in the backup");
    ok(SOSAccountHasPublicKey(alice_account, &error), "Has Public Key" );
    ok([alice_account.trust resetAccountToEmpty:alice_account transport:alice_account.circle_transport err:&error], "Reset circle to empty");
    CFReleaseNull(error);
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 2, "updates");
    ok(SOSAccountIsBackupRingEmpty(bob_account, kTestView1), "Bob should not be in the backup");
    ok(SOSAccountIsBackupRingEmpty(bob_account, kSOSViewiCloudIdentity), "Bob should not be in the backup");
    ok(SOSAccountIsBackupRingEmpty(alice_account, kTestView1), "Alice should not be in the backup");
    ok(SOSAccountIsBackupRingEmpty(alice_account, kSOSViewiCloudIdentity), "Alice should not be in the backup");


    CFReleaseNull(cfpassword);
    alice_account = nil;
    bob_account = nil;
    SOSTestCleanup();
}
#endif

int secd_62_account_backup(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(98);
    enableSOSCompatibilityForTests();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    secd_test_setup_testviews(); // for running this test solo
    tests();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
