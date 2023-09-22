//
//  secd-100-initialsync.c
//  sec
//


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


#include <Security/SecBase.h>
#include <Security/SecItem.h>

#include <CoreFoundation/CFDictionary.h>

#include "keychain/SecureObjectSync/SOSAccount.h"
#include <Security/SecureObjectSync/SOSCloudCircle.h>
#include "keychain/SecureObjectSync/SOSInternal.h"
#include "keychain/SecureObjectSync/SOSUserKeygen.h"
#include "keychain/SecureObjectSync/SOSTransport.h"

#include <stdlib.h>
#include <unistd.h>

#include "secd_regressions.h"
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
    CFSetRef initialSyncViews = SOSViewCopyViewSet(kViewSetInitial);
    CFMutableSetRef alwaysOnViews = SOSViewCopyViewSet(kViewSetAlwaysOn);
    CFSetRef defaultViews = SOSViewCopyViewSet(kViewSetDefault);
    int initialSyncViewCount = (int) CFSetGetCount(initialSyncViews);
    CFReleaseNull(initialSyncViews);
    CFSetRef backupSyncViews = SOSViewCopyViewSet(kViewSetRequiredForBackup);
    int backupSyncViewCount = (int) CFSetGetCount(backupSyncViews);
    CFReleaseNull(backupSyncViews);
    int expectedStartupViewCount;

    if(initialSyncViewCount == 0) {
        CFSetUnion(alwaysOnViews, defaultViews);
        expectedStartupViewCount = (int) CFSetGetCount(alwaysOnViews);
    } else {
        CFMutableSetRef isViews = CFSetCreateMutableCopy(kCFAllocatorDefault, 0, initialSyncViews);
        CFSetUnion(isViews, backupSyncViews);
        expectedStartupViewCount = (int) CFSetGetCount(isViews);
        CFReleaseNull(isViews);
    }
    CFReleaseNull(alwaysOnViews);
    CFReleaseNull(defaultViews);



    CFMutableDictionaryRef changes = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);

    SOSDataSourceFactoryRef test_factory = SOSTestDataSourceFactoryCreate();
    SOSDataSourceRef test_source = SOSTestDataSourceCreate();
    SOSTestDataSourceFactorySetDataSource(test_factory, CFSTR("TestType"), test_source);
    
    SOSAccount* alice_account = CreateAccountForLocalChanges(CFSTR("AliceAccount"),CFSTR("TestType") );
    SOSAccount* bob_account = CreateAccountForLocalChanges(CFSTR("BobAccount"),CFSTR("TestType") );
    
    ok(SOSAccountAssertUserCredentialsAndUpdate(alice_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);

    ok(SOSAccountJoinCircles_wTxn(alice_account, &error), "Join circle: %@", error);
    ok(SOSAccountCheckHasBeenInSync_wTxn(alice_account), "Alice account initial sync done");

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 1, "updates");

    ok(SOSAccountAssertUserCredentialsAndUpdate(bob_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);
    CFReleaseNull(cfpassword);
    
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

    
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 3, "updates");
    
    accounts_agree("bob&alice pair", bob_account, alice_account);

    if(initialSyncViewCount > 0) {
        ok(!SOSAccountCheckHasBeenInSync_wTxn(bob_account), "Bob should not be initially synced");
    }
    CFSetRef bob_viewSet = SOSPeerInfoCopyEnabledViews(bob_account.peerInfo);
    is(CFSetGetCount(bob_viewSet), expectedStartupViewCount, "bob's initial view set should be just the initial sync and backup views");
    CFReleaseNull(bob_viewSet);

    if(initialSyncViewCount > 0) {
        ok(!SOSAccountCheckHasBeenInSync_wTxn(bob_account), "Bob should not be initially synced");
    }

    SOSAccountPeerGotInSync_wTxn(bob_account, alice_account.peerInfo);

    if(initialSyncViewCount > 0) {
        bob_viewSet = SOSPeerInfoCopyEnabledViews(bob_account.peerInfo);
        is(CFSetGetCount(bob_viewSet), backupSyncViewCount, "bob's initial view set should be just the back up");
        CFReleaseNull(bob_viewSet);
    } else {
        ok(true, "don't mess with the total test count");
    }
    bob_account = nil;
    alice_account = nil;
    
    SOSDataSourceFactoryRelease(test_factory);

    SOSTestCleanup();
}
#endif

int secd_100_initialsync(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(33);
    enableSOSCompatibilityForTests();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    tests();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
