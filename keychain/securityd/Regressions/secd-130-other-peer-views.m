//
//  secd-130-other-peer-views.m
//  sec
//
//  Created by Mitch Adler on 7/9/16.
//
//

#include <stdlib.h>
#include <unistd.h>

#include "secd_regressions.h"

#include "SOSRegressionUtilities.h"
#include <utilities/SecCFWrappers.h>
#include <Security/SecKeyPriv.h>

#include "SecdTestKeychainUtilities.h"

#include "SOSAccountTesting.h"

#include "keychain/SecureObjectSync/SOSAccount.h"
#if SOS_ENABLED

#define kAccountPasswordString ((uint8_t*) "FooFooFoo")
#define kAccountPasswordStringLen 10

static void tests(void) {
    CFErrorRef error = NULL;

    // Unretained aliases.
    CFDataRef cfpassword = CFDataCreate(NULL, kAccountPasswordString, kAccountPasswordStringLen);
    CFStringRef cfaccount = CFSTR("test@test.org");
    CFMutableDictionaryRef cfchanges = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFSetRef initialSyncViews = SOSViewCopyViewSet(kViewSetInitial);
    int initialSyncViewCount = (int) CFSetGetCount(initialSyncViews);
    CFReleaseNull(initialSyncViews);

    SOSAccount* alice_account = CreateAccountForLocalChanges(CFSTR("Alice"), CFSTR("TestSource"));
    SOSAccount* bob_account = CreateAccountForLocalChanges(CFSTR("Bob"), CFSTR("TestSource"));
    SOSAccount* carole_account = CreateAccountForLocalChanges(CFSTR("Carole"), CFSTR("TestSource"));
    SOSAccount* david_account = CreateAccountForLocalChanges(CFSTR("David"), CFSTR("TestSource"));

    CFArrayRef aView = CFArrayCreateForCFTypes(kCFAllocatorDefault,
                                                   kSOSViewPCSMasterKey,
                                                   NULL);

    CFArrayRef wifiView = CFArrayCreateForCFTypes(kCFAllocatorDefault,
                                                  kSOSViewWiFi,
                                                  NULL);

    CFArrayRef otherView = CFArrayCreateForCFTypes(kCFAllocatorDefault,
                                                  kSOSViewOtherSyncable,
                                                  NULL);

    CFArrayRef otherAndWifiViews = CFArrayCreateForCFTypes(kCFAllocatorDefault,
                                                           kSOSViewWiFi,
                                                           kSOSViewOtherSyncable,
                                                           NULL);

    is(SOSAccountPeersHaveViewsEnabled(carole_account, aView, &error), NULL, "Peer views empty (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountAssertUserCredentialsAndUpdate(bob_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);

    // Bob wins writing at this point, feed the changes back to alice.
    is(ProcessChangesUntilNoChange(cfchanges, alice_account, bob_account, carole_account, david_account, NULL), 1, "updates");

    ok(SOSAccountAssertUserCredentialsAndUpdate(alice_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountAssertUserCredentialsAndUpdate(carole_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountAssertUserCredentialsAndUpdate(david_account, cfaccount, cfpassword, &error), "Credential setting (%@)", error);
    CFReleaseNull(cfpassword);
    CFReleaseNull(error);

    ok(SOSAccountResetToOffering_wTxn(alice_account, &error), "Reset to offering (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(cfchanges, alice_account, bob_account, carole_account, david_account, NULL), 2, "updates");

    is(SOSAccountPeersHaveViewsEnabled(alice_account, aView, &error), kCFBooleanFalse, "Peer views empty (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountJoinCircles_wTxn(bob_account, &error), "Bob Applies (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountJoinCircles_wTxn(carole_account, &error), "Carole Applies too (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountJoinCircles_wTxn(david_account, &error), "David Applies too (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(cfchanges, alice_account, bob_account, carole_account, david_account, NULL), 4, "updates");

    is(SOSAccountPeersHaveViewsEnabled(carole_account, aView, &error), NULL, "Peer views empty (%@)", error);
    CFReleaseNull(error);

    {
        CFArrayRef applicants = SOSAccountCopyApplicants(alice_account, &error);

        ok(applicants && CFArrayGetCount(applicants) == 3, "See three applicants %@ (%@)", applicants, error);
        CFReleaseNull(error);
        ok(SOSAccountAcceptApplicants(alice_account, applicants, &error), "Accept bob into the fold");
        CFReleaseNull(error);
        CFReleaseSafe(applicants);
    }

    is(ProcessChangesUntilNoChange(cfchanges, alice_account, bob_account, carole_account, david_account, NULL), 5, "updates");

    // Make all views work buy finishing initial sync.
    SOSAccountPeerGotInSync_wTxn(bob_account, alice_account.peerInfo);
    SOSAccountPeerGotInSync_wTxn(carole_account, alice_account.peerInfo);
    SOSAccountPeerGotInSync_wTxn(david_account, alice_account.peerInfo);

    int changeCount = (initialSyncViewCount) ? 4 : 1;
    is(ProcessChangesUntilNoChange(cfchanges, alice_account, bob_account, carole_account, david_account, NULL), changeCount, "updates");

    is(SOSAccountPeersHaveViewsEnabled(alice_account, aView, &error), kCFBooleanTrue, "Peer views empty (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(alice_account, wifiView, &error), kCFBooleanFalse, "Peer views empty (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountUpdateView_wTxn(alice_account, kSOSViewWiFi, kSOSCCViewEnable, &error), "Enable view (%@)", error);
    CFReleaseNull(error);

    ok(SOSAccountUpdateView_wTxn(bob_account, kSOSViewOtherSyncable, kSOSCCViewEnable, &error), "Enable view (%@)", error);
    CFReleaseNull(error);

    is(ProcessChangesUntilNoChange(cfchanges, alice_account, bob_account, carole_account, david_account, NULL), 3, "updates");

    is(SOSAccountPeersHaveViewsEnabled(alice_account, wifiView, &error), kCFBooleanFalse, "Wifi view for Alice (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(alice_account, otherView, &error), kCFBooleanTrue, "other view for Alice (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(alice_account, otherAndWifiViews, &error), kCFBooleanFalse, "both for Alice (%@)", error);
    CFReleaseNull(error);
    
    is(SOSAccountPeersHaveViewsEnabled(bob_account, wifiView, &error), kCFBooleanTrue, "Wifi view for Bob (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(bob_account, otherView, &error), kCFBooleanFalse, "other view for Bob (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(bob_account, otherAndWifiViews, &error), kCFBooleanFalse, "both for Bob (%@)", error);
    CFReleaseNull(error);
    
    is(SOSAccountPeersHaveViewsEnabled(carole_account, wifiView, &error), kCFBooleanTrue, "Wifi view for Carole (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(carole_account, otherView, &error), kCFBooleanTrue, "other view for Carole (%@)", error);
    CFReleaseNull(error);

    is(SOSAccountPeersHaveViewsEnabled(carole_account, otherAndWifiViews, &error), kCFBooleanTrue, "both for Carole (%@)", error);
    CFReleaseNull(error);

    CFReleaseNull(aView);
    CFReleaseNull(wifiView);
    CFReleaseNull(otherView);
    CFReleaseNull(otherAndWifiViews);

    SOSTestCleanup();
}
#endif

int secd_130_other_peer_views(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(72);
    enableSOSCompatibilityForTests();
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    secd_test_clear_testviews();
    tests();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
#else
    plan_tests(0);
#endif
    return 0;
}
