/*
 * Copyright (c) 2012-2016 Apple Inc. All Rights Reserved.
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
//  secd-80-views-alwayson.c
//  Security
//
//
//


#include <CoreFoundation/CFDictionary.h>
#include <utilities/SecCFWrappers.h>

#include "keychain/SecureObjectSync/SOSAccount.h"

#include "secd_regressions.h"
#include "SOSAccountTesting.h"
#include "SecdTestKeychainUtilities.h"
#if SOS_ENABLED

static void testView(SOSAccount* account, SOSViewResultCode expected, CFStringRef view, SOSViewActionCode action, char *label) {
    CFErrorRef error = NULL;
    SOSViewResultCode vcode = 9999;
    switch(action) {
        case kSOSCCViewQuery:
            vcode = [account.trust viewStatus:account name:view err:&error];
            break;
        case kSOSCCViewEnable:
        case kSOSCCViewDisable: // fallthrough
            vcode = [account.trust updateView:account name:view code:action err:&error];
            break;
        default:
            break;
    }
    is(vcode, expected, "%s (%@)", label, error);
    CFReleaseNull(error);
}

/*
 Make a circle with two peers - alice and bob
 Check for ContinuityUnlock View on Alice - it should be there
 turn off ContinuityUnlock on Alice
 Change the password with Bob - makeing Alice invalid
 Update Alice with the new password
 see that ContinuityUnlock is automatically back on because it's "always on"
 */

static void alwaysOnTest(void)
{
    CFDataRef cfpassword = CFDataCreate(NULL, (uint8_t *) "FooFooFoo", 10);
    CFDataRef cfpasswordNew = CFDataCreate(NULL, (uint8_t *) "FooFooFo2", 10);
    CFStringRef cfaccount = CFSTR("test@test.org");
    
    CFMutableDictionaryRef changes = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    SOSAccount* alice_account = CreateAccountForLocalChanges(CFSTR("Alice"), CFSTR("TestSource"));
    SOSAccount* bob_account = CreateAccountForLocalChanges(CFSTR("Bob"), CFSTR("TestSource"));
    
    // Start Circle
    ok(SOSTestStartCircleWithAccount(alice_account, changes, cfaccount, cfpassword), "Have Alice start a circle");
    is(ProcessChangesUntilNoChange(changes, alice_account, bob_account, NULL), 1, "updates");
    ok(SOSTestJoinWithApproval(cfpassword, cfaccount, changes, alice_account, bob_account, KEEP_USERKEY, 2, false), "Bob Joins");
    CFReleaseNull(cfpassword);

    testView(alice_account, kSOSCCViewMember, kSOSViewContinuityUnlock, kSOSCCViewQuery, "Expected view capability for kSOSViewContinuityUnlock");
    testView(alice_account, kSOSCCViewMember, kSOSViewContinuityUnlock, kSOSCCViewDisable, "Not expected to disable kSOSViewContinuityUnlock - it's always-on");

    ok(SOSAccountAssertUserCredentialsAndUpdate(bob_account, cfaccount, cfpasswordNew, NULL), "Bob changes the password");
    testView(alice_account, kSOSCCViewMember, kSOSViewContinuityUnlock, kSOSCCViewQuery, "Expected  kSOSViewContinuityUnlock is on for alice still");
    ok(SOSAccountAssertUserCredentialsAndUpdate(alice_account, cfaccount, cfpasswordNew, NULL), "Alice sets the new password");
    CFReleaseNull(cfpasswordNew);
    testView(alice_account, kSOSCCViewMember, kSOSViewContinuityUnlock, kSOSCCViewQuery, "Expected view capability for kSOSViewContinuityUnlock");

    CFReleaseNull(changes);
    
    SOSTestCleanup();
}
#endif

int secd_80_views_alwayson(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(35);
    enableSOSCompatibilityForTests();
    secd_test_clear_testviews();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    alwaysOnTest();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
