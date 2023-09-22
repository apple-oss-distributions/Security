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
#include "keychain/SecureObjectSync/SOSTransport.h"

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

#define kAccountPasswordString ((uint8_t*) "FooFooFoo")
#define kAccountPasswordStringLen 10

static void tests(void)
{
    CFErrorRef error = NULL;
    CFDataRef cfpassword = CFDataCreate(NULL, kAccountPasswordString, kAccountPasswordStringLen);
    CFStringRef cfaccount = CFSTR("test@test.org");

    CFMutableDictionaryRef changes = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);

    SOSAccount* alice_account = CreateAccountForLocalChanges(CFSTR("Alice"), CFSTR("TestSource"));
    SOSAccount* bob_account = CreateAccountForLocalChanges(CFSTR("Bob"), CFSTR("TestSource"));
    SOSAccount* carole_account = CreateAccountForLocalChanges(CFSTR("Carole"), CFSTR("TestSource"));
    SOSAccount* david_account = CreateAccountForLocalChanges(CFSTR("David"), CFSTR("TestSource"));
    
    ok(SOSAccountAssertUserCredentialsAndUpdate(bob_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    
    // Bob wins writing at this point, feed the changes back to alice.
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 1, "updates");

    ok(SOSAccountAssertUserCredentialsAndUpdate(alice_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);
    
    ok(SOSAccountAssertUserCredentialsAndUpdate(carole_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);
    
    ok(SOSAccountAssertUserCredentialsAndUpdate(david_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(cfpassword);
    CFReleaseNull(error);
    
    ok(SOSAccountResetToOffering_wTxn(alice_account, &error), "Reset to offering (%@)", error);
    CFReleaseNull(error);
    
    // Lost Application Scenario
    is(ProcessChangesOnce(changes, alice_account, bob_account, carole_account, david_account, NULL), 1, "updates");

    ok(SOSAccountJoinCircles_wTxn(bob_account, &error), "Bob Applies (%@)", error);
    CFReleaseNull(error);
    
    ok(SOSAccountJoinCircles_wTxn(carole_account, &error), "Carole Applies too (%@)", error);
    CFReleaseNull(error);
    
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 3, "updates");
    
    accounts_agree("alice and carole agree", alice_account, carole_account);
    accounts_agree("alice and bob agree", alice_account, bob_account);
    
    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);
        
        ok(applicants && CFArrayGetCount(applicants) == 2, "See two applicants %@ (%@)", applicants, error);
        CFReleaseNull(error);
        CFReleaseSafe(applicants);
    }
    
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 1, "updates");

    accounts_agree("alice and carole agree", alice_account, carole_account);

    CFReleaseNull(error);
    
    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);
        ok(applicants && CFArrayGetCount(applicants) == 2, "See two applicants %@ (%@)", applicants, error);
        ok(SOSAccountRejectApplicants(alice_account, applicants, &error), "Everyone out the pool");
        CFReleaseNull(error);
        CFReleaseSafe(applicants);
    }

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 2, "updates");

    accounts_agree("alice and carole agree", alice_account, carole_account);

    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);
        ok(applicants && CFArrayGetCount(applicants) == 0, "See no applicants %@ (%@)", applicants, error);
        CFReleaseNull(error);
        CFReleaseSafe(applicants);
    }
    
    ok([carole_account.trust leaveCircle:carole_account err:&error], "Carole bails (%@)", error);
    CFReleaseNull(error);

    // Everyone but bob sees that carole bails.
    is(ProcessChangesUntilNoChange(changes, alice_account, carole_account, david_account, NULL), 1, "updates");


    // Bob reapplies, but it's to an old circle.
    ok(SOSAccountJoinCircles_wTxn(bob_account, &error), "Bob asks again");
    CFReleaseNull(error);

    // Bob returns and we mix our split worlds up.
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 2, "updates");

    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);
        ok(applicants && CFArrayGetCount(applicants) == 1, "See one applicants %@ (%@)", applicants, error);
        CFReleaseNull(error);
        ok(SOSAccountAcceptApplicants(alice_account, applicants, &error), "Accept bob into the fold");
        CFReleaseNull(error);
        CFReleaseSafe(applicants);
    }

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 3, "updates");

    is(countPeers(bob_account), 2, "Bob sees 2 valid peers after admission from re-apply");

    accounts_agree("alice and bob agree", alice_account, bob_account);
    accounts_agree_internal("alice and carole agree", alice_account, carole_account, false);


    // Rejected Application Scenario
    ok(SOSAccountJoinCircles_wTxn(david_account, &error), "Dave Applies (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 2, "updates");

    accounts_agree_internal("alice and david agree", alice_account, david_account, false);

    SOSAccountPurgePrivateCredential(alice_account);

    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);

        ok(applicants && CFArrayGetCount(applicants) == 1, "See one applicant %@ (%@)", applicants, error);
        ok(SOSAccountRejectApplicants(alice_account, applicants, &error), "Alice rejects (%@)", error);
        CFReleaseNull(error);
        CFReleaseNull(applicants);
    }

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 2, "updates");

    accounts_agree_internal("alice and carole still agree after david is rejected", alice_account, carole_account, false);

    cfpassword = CFDataCreate(NULL, kAccountPasswordString, kAccountPasswordStringLen);

    ok(SOSAccountTryUserCredentials(alice_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);
    CFReleaseNull(cfpassword);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 1, "updates");

    accounts_agree("bob&alice pair", bob_account, alice_account);

    ok(SOSAccountJoinCirclesAfterRestore_wTxn(carole_account, &error), "Carole cloud identiy joins (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, carole_account, david_account, NULL), 4, "updates");

    accounts_agree_internal("carole&alice pair", carole_account, alice_account, false);

    is(countPeers(carole_account), 3, "Carole sees 3 valid peers after sliding in");

    alice_account = nil;
    bob_account = nil;
    SOSTestCleanup();
}
#endif

int secd_56_account_apply(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(181);
    enableSOSCompatibilityForTests();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    tests();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
