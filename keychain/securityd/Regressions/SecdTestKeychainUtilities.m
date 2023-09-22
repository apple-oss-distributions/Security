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


#include "SecdTestKeychainUtilities.h"

#include <regressions/test/testmore.h>
#include <utilities/SecFileLocations.h>
#include <utilities/SecCFWrappers.h>
#include "keychain/securityd/SecItemServer.h"
#include <Security/SecureObjectSync/SOSViews.h>

#include "keychain/securityd/SecItemDataSource.h"

#import "Analytics/Clients/SOSAnalytics.h"


#include <CoreFoundation/CoreFoundation.h>

//#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

void secd_test_setup_temp_keychain(const char* test_prefix, dispatch_block_t do_in_reset)
{
    CFStringRef tmp_dir = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/tmp/%s.%X/"), test_prefix, arc4random());
    CFStringRef keychain_dir = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%@Library/Keychains"), tmp_dir);
    secnotice("secdtest", "Keychain path: %@", keychain_dir);
    
    CFStringPerformWithCString(keychain_dir, ^(const char *keychain_dir_string) {
        errno_t err = mkpath_np(keychain_dir_string, 0755);
        ok(err == 0 || err == EEXIST, "Create temp dir %s (%d)", keychain_dir_string, err);
    });
    
    
    /* set custom keychain dir, reset db */
    SecSetCustomHomeURLString(tmp_dir);

    SecKeychainDbReset(do_in_reset);

    CFReleaseNull(tmp_dir);
    CFReleaseNull(keychain_dir);
}

bool secd_test_teardown_delete_temp_keychain(const char* test_prefix)
{
    NSURL* keychainDir = (NSURL*)CFBridgingRelease(SecCopyHomeURL());

    // Drop analytics dbs here
    [[SOSAnalytics logger] removeStateAndUnlinkFile:NO];

    secd_test_clear_testviews();
    SecItemDataSourceFactoryReleaseAll();
    SecKeychainDbForceClose();
    SecKeychainDbReset(NULL);

    // Only perform the desctructive step if the url matches what we expect!
    NSString* testName = [NSString stringWithUTF8String:test_prefix];

    if([keychainDir.path hasPrefix:[NSString stringWithFormat:@"/tmp/%@.", testName]]) {
        secnotice("secd_tests", "Removing test-specific keychain directory at %@", keychainDir);

        NSError* removeError = nil;
        [[NSFileManager defaultManager] removeItemAtURL:keychainDir error:&removeError];
        if(removeError) {
            secnotice("secd_tests", "Failed to remove directory: %@", removeError);
            return false;
        }

        return true;
     } else {
         secnotice("secd_tests", "Not removing keychain directory (%@), as it doesn't appear to be test-specific (for test %@)", keychainDir.path, testName);
         return false;
    }
}

CFStringRef kTestView1 = CFSTR("TestView1");
CFStringRef kTestView2 = CFSTR("TestView2");

void secd_test_setup_testviews(void) {    
    CFMutableSetRef testViews = CFSetCreateMutableForCFTypes(kCFAllocatorDefault);
    CFSetAddValue(testViews, kTestView1);
    CFSetAddValue(testViews, kTestView2);
    
    SOSViewsSetTestViewsSet(testViews);
    CFReleaseNull(testViews);
}

void secd_test_clear_testviews(void) {
    SOSViewsSetTestViewsSet(NULL);
}


