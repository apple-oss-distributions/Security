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


#include "secd_regressions.h"

#include "keychain/securityd/SecDbItem.h"
#include <utilities/SecCFWrappers.h>
#include <utilities/SecFileLocations.h>
#include <utilities/fileIo.h>

#include "keychain/securityd/SOSCloudCircleServer.h"
#include "keychain/securityd/SecItemServer.h"

#include <Security/SecBasePriv.h>

#include <AssertMacros.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <pthread.h>

#include "SecdTestKeychainUtilities.h"

/* Corrupt 1st and 3rd item */
static const char *corrupt_item_sql = "UPDATE inet SET data=X'12345678' WHERE rowid=1 OR rowid=3";

int secd_04_corrupted_items(int argc, char *const *argv)
{
    plan_tests(12 + kSecdTestSetupTestCount);
    
    /* custom keychain dir */
    secd_test_setup_temp_keychain("secd_04_corrupted_items", NULL);

    /* add a password */
    CFTypeRef ref1 = NULL;
    int v_eighty = 80;
    CFNumberRef eighty = CFNumberCreate(NULL, kCFNumberSInt32Type, &v_eighty);
    const char *v_data = "test";
    CFDataRef pwdata = CFDataCreate(NULL, (UInt8 *)v_data, strlen(v_data));
    CFMutableDictionaryRef query = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionaryAddValue(query, kSecClass, kSecClassInternetPassword);
    CFDictionaryAddValue(query, kSecAttrServer, CFSTR("corrupt.spamcop.net"));
    CFDictionaryAddValue(query, kSecAttrAccount, CFSTR("smith"));
    CFDictionaryAddValue(query, kSecAttrPort, eighty);
    CFDictionaryAddValue(query, kSecAttrProtocol, kSecAttrProtocolHTTP);
    CFDictionaryAddValue(query, kSecAttrAuthenticationType, kSecAttrAuthenticationTypeDefault);
    CFDictionaryAddValue(query, kSecValueData, pwdata);
    CFDictionaryAddValue(query, kSecReturnPersistentRef, kCFBooleanTrue);
    ok_status(SecItemAdd(query, &ref1), "add internet password port 80");

    /* add another one */
    CFTypeRef ref2 = NULL;
    int v_eighty_one = 81;
    CFNumberRef eighty_one = CFNumberCreate(NULL, kCFNumberSInt32Type, &v_eighty_one);
    CFDictionarySetValue(query, kSecAttrPort, eighty_one);
    ok_status(SecItemAdd(query, &ref2), "add internet password port 81");

    /* add another one */
    CFTypeRef ref3 = NULL;
    int v_eighty_two = 82;
    CFNumberRef eighty_two = CFNumberCreate(NULL, kCFNumberSInt32Type, &v_eighty_two);
    CFDictionarySetValue(query, kSecAttrPort, eighty_two);
    ok_status(SecItemAdd(query, &ref3), "add internet password port 82");

    /* remove the data, and return key from the query */
    CFDictionaryRemoveValue(query, kSecValueData);
    CFDictionaryRemoveValue(query, kSecReturnPersistentRef);

    /* update second password to conflict with first one */
    CFDictionarySetValue(query, kSecAttrPort, eighty_one);
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionaryAddValue(attributes, kSecAttrPort, eighty);
    is_status(SecItemUpdate(query, attributes), errSecDuplicateItem, "update internet password port 80 to 81");

    /* corrupt the first and 3rd password */
    CFStringRef keychain_path_cf = SecServerKeychainCopyPath();

    CFStringPerformWithCString(keychain_path_cf, ^(const char *keychain_path) {
        /* Create a new keychain sqlite db */
        sqlite3 *db;
        
        is(sqlite3_open(keychain_path, &db), SQLITE_OK, "open keychain");
        is(sqlite3_exec(db, corrupt_item_sql, NULL, NULL, NULL), SQLITE_OK,
           "corrupting keychain items");

        is(sqlite3_close_v2(db), SQLITE_OK,
           "Should be able to close db");
    });

    /* Try the update again */
    ok_status(SecItemUpdate(query, attributes), "update internet password port 80 to 81 (after corrupting item)");

    /* query the persistent ref */
    CFTypeRef ref = NULL;
    CFDictionarySetValue(query, kSecAttrPort, eighty);
    CFDictionaryAddValue(query, kSecReturnPersistentRef, kCFBooleanTrue);
    ok_status(SecItemCopyMatching(query, &ref), "Item 80 found");
    
    CFDictionaryRemoveValue(query, kSecReturnPersistentRef);
    ok(CFEqual(ref, ref2), "persistent ref of item 2");

    CFReleaseNull(attributes);
    
    /* Update the 3rd item (82) */
    CFDictionarySetValue(query, kSecAttrPort, eighty_two);

    attributes = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    CFDictionaryAddValue(attributes, kSecAttrLabel, CFSTR("This is the 3rd password"));
    is_status(SecItemUpdate(query, attributes), errSecItemNotFound, "update internet password port 82 (after corrupting item)");

    CFDictionarySetValue(query, kSecValueData, pwdata);
    ok_status(SecItemAdd(query, NULL), "re-adding internet password port 82 (after corrupting item)");
    CFReleaseNull(pwdata);
    CFReleaseNull(attributes);
    CFReleaseNull(query);
    CFReleaseNull(eighty);
    CFReleaseNull(eighty_one);
    CFReleaseNull(eighty_two);

    secd_test_teardown_delete_temp_keychain("secd_04_corrupted_items");

    return 0;
}
