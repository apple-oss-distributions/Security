/*
 * Copyright (c) 2016 Apple Inc. All Rights Reserved.
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

#import <Foundation/Foundation.h>
#include <Security/Security.h>

#include <utilities/SecCFWrappers.h>
#include "SecDbKeychainItem.h"

#include <TargetConditionals.h>

#if USE_KEYSTORE
#include "OSX/utilities/SecAKSWrappers.h"

#include "SecdTestKeychainUtilities.h"

int secd_36_ks_encrypt(int argc, char *const *argv)
{
    plan_tests(11 + kSecdTestSetupTestCount);

    secd_test_setup_temp_keychain("secd_36_ks_encrypt", NULL);

    keybag_handle_t keybag;
    keybag_state_t state;
    CFDictionaryRef data = NULL;
    CFDataRef enc = NULL;
    CFErrorRef error = NULL;
    SecAccessControlRef ac = NULL;
    bool ret;

    char passcode[] = "password";
    int passcode_len = sizeof(passcode) - 1;


    /* Create and lock custom keybag */
    is(kAKSReturnSuccess, aks_create_bag(passcode, passcode_len, kAppleKeyStoreDeviceBag, &keybag), "create keybag");
    is(kAKSReturnSuccess, aks_get_lock_state(keybag, &state), "get keybag state");
    is(0, (int)(state&keybag_state_locked), "keybag unlocked");

    data = (__bridge CFDictionaryRef)@{
        (id)kSecValueData : @"secret here",
    };

    ok(ac = SecAccessControlCreate(NULL, &error), "SecAccessControlCreate: %@", error);
    ok(SecAccessControlSetProtection(ac, kSecAttrAccessibleWhenUnlocked, &error), "SecAccessControlSetProtection: %@", error);

    CFDictionaryRef empty = (__bridge CFDictionaryRef)@{};
    ret = ks_encrypt_data(keybag, ac, NULL, data, (__bridge CFDictionaryRef)@{@"persistref" : @"aaa-bbb-ccc"}, empty, &enc, true, false, &error);
    is(true, ret);

    CFReleaseNull(ac);

    {
        CFMutableDictionaryRef attributes = NULL;
        uint32_t version = 0;

        NSData* dummyACM = [NSData dataWithBytes:"dummy" length:5];
        const SecDbClass* class = kc_class_with_name(kSecClassGenericPassword);
        NSArray* dummyArray = [NSArray array];

        ret = ks_decrypt_data(keybag, NULL, kAKSKeyOpDecrypt, &ac, (__bridge CFDataRef _Nonnull)dummyACM, enc, class, (__bridge CFArrayRef)dummyArray, &attributes, &version, true, NULL, &error);
        is(true, ret, "ks_decrypt_data: %@", error);

        CFTypeRef aclProtection = ac ? SecAccessControlGetProtection(ac) : NULL;
        ok(aclProtection && CFEqual(aclProtection, kSecAttrAccessibleWhenUnlocked), "AccessControl protection is: %@", aclProtection);

        CFReleaseNull(ac);
    }

    CFReleaseNull(error);
    CFReleaseNull(enc);

    secd_test_teardown_delete_temp_keychain("secd_36_ks_encrypt");

    void* buf = NULL;
    int bufLen = 0;
    ok(kAKSReturnSuccess == aks_save_bag(keybag, &buf, &bufLen), "failed to save keybag for invalidation");
    ok(kAKSReturnSuccess == aks_unload_bag(keybag), "failed to unload keybag for invalidation");
    ok(kAKSReturnSuccess == aks_invalidate_bag(buf, bufLen), "failed to invalidate keybag");
    free(buf);

    return 0;
}

#else /* !USE_KEYSTORE */

int secd_36_ks_encrypt(int argc, char *const *argv)
{
    plan_tests(1);
    ok(true);
    return 0;
}
#endif /* USE_KEYSTORE */
