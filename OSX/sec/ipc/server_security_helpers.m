/*
 * Copyright (c) 2017 Apple Inc. All Rights Reserved.
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

#include <pthread/pthread.h>

#include <TargetConditionals.h>
#include "utilities/SecAKSWrappers.h"
#if __has_include(<MobileKeyBag/MobileKeyBag.h>) && TARGET_HAS_KEYSTORE
#include <MobileKeyBag/MobileKeyBag.h>
#define HAVE_MOBILE_KEYBAG_SUPPORT 1
#endif

#include "server_security_helpers.h"
#include "server_entitlement_helpers.h"

#include <Security/SecTask.h>
#include <Security/SecTaskPriv.h>
#include "ipc/securityd_client.h"
#include <Security/SecEntitlements.h>
#include "sectask/SystemEntitlements.h"
#include "utilities/SecInternalReleasePriv.h"
#include <sys/codesign.h>
#include <Security/SecItem.h>
#include "utilities/SecCFRelease.h"
#include "utilities/SecCFWrappers.h"
#include "utilities/debugging.h"
#include "keychain/securityd/SecDbQuery.h"

#if __has_include(<UserManagement/UserManagement.h>)
#include <UserManagement/UserManagement.h>
#endif

#if TARGET_OS_IOS && HAVE_MOBILE_KEYBAG_SUPPORT
bool device_is_multiuser(void)
{
    static dispatch_once_t once;
    static bool result;

    dispatch_once(&once, ^{
        CFDictionaryRef deviceMode = MKBUserTypeDeviceMode(NULL, NULL);
        CFTypeRef value = NULL;

        if (deviceMode && CFDictionaryGetValueIfPresent(deviceMode, kMKBDeviceModeKey, &value) && CFEqual(value, kMKBDeviceModeMultiUser)) {
            result = true;
        }
        CFReleaseNull(deviceMode);
    });

    return result;
}
#endif /* HAVE_MOBILE_KEYBAG_SUPPORT && TARGET_OS_IOS */

static bool securityCheckClientAccessGroups(SecurityClient* client) {
    if (!client->accessGroups) {
        return true;
    }

    CFRange range = { 0, CFArrayGetCount(client->accessGroups) };
    if (!CFArrayContainsValue(client->accessGroups, range, CFSTR("*"))) {
        return true;
    }

    CFMutableArrayRef allowedIdentifiers = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
#if TARGET_OS_OSX
    CFArrayAppendValue(allowedIdentifiers, CFSTR("com.apple.keychainaccess"));
#endif
    if (SecIsInternalRelease()) {
        CFArrayAppendValue(allowedIdentifiers, CFSTR("com.apple.security-cli"));
    }

    bool answer = SecTaskIsEligiblePlatformBinary(client->task, allowedIdentifiers);
    CFReleaseNull(allowedIdentifiers);

    return answer;
}

bool SecFillSecurityClientMuser(SecurityClient *client)
{
    if (!client) {
        return false;
    }
    @autoreleasepool {
#if KEYCHAIN_SUPPORTS_PERSONA_MULTIUSER
        /*
         * iOS+macOS supports Enterprise Data Separation.
         * tvOS supports guest users.
         * Use the appropriate musr values for either.
         */
        
        if (!client->isMusrOverridden) {
            CFReleaseNull(client->musr);
        }
        
        UMUserPersona *persona = [[UMUserManager sharedManager] currentPersona];
        if (persona &&
#if TARGET_OS_IOS || TARGET_OS_OSX
            persona.userPersonaType == UMUserPersonaTypeEnterprise
#elif TARGET_OS_TV
            persona.userPersonaType == UMUserPersonaTypeGuest
#else
#error Keychain does not support persona multiuser on this platform
#endif
        ) {
            secinfo("serverxpc", "securityd client(%p): persona user %@", client, persona.userPersonaNickName);
            secnotice("serverxpc", "securityd client(%p): persona uuid %@", client, persona.userPersonaUniqueString);
            uuid_t uuid;

            if (uuid_parse([persona.userPersonaUniqueString UTF8String], uuid) != 0) {
                secnotice("serverxpc", "securityd client(%p):  uuid %@ didn't parse setting to null", client, persona.userPersonaUniqueString);
                client->musr = NULL;
                return false;
            }
            client->musr = CFDataCreate(NULL, uuid, sizeof(uuid_t));
        } 
#endif /* KEYCHAIN_SUPPORTS_PERSONA_MULTIUSER */
    }
    return true;
}

bool
fill_security_client(SecurityClient * client, const uid_t uid, audit_token_t auditToken) {
    if(!client) {
        return false;
    }

    @autoreleasepool {
        
        client->uid = uid;
        client->musr = NULL;

#if KEYCHAIN_SUPPORTS_EDU_MODE_MULTIUSER && HAVE_MOBILE_KEYBAG_SUPPORT
        if (device_is_multiuser()) {
            CFErrorRef error = NULL;

            client->inEduMode = true;
            client->activeUser = MKBForegroundUserSessionID(&error);
            if (client->activeUser == -1 || client->activeUser == 0) {
                assert(0);
                client->activeUser = 0;
            }

            /*
             * If we are a edu mode user, and its not the active user,
             * then the request is coming from inside the syncbubble.
             *
             * otherwise we are going to execute the request as the
             * active user.
             */

            if (client->uid > 501 && (uid_t)client->activeUser != client->uid) {
                secinfo("serverxpc", "securityd client: sync bubble user");
                client->musr = SecMUSRCreateSyncBubbleUserUUID(client->uid);
                client->keybag = KEYBAG_DEVICE;
            } else {
                secinfo("serverxpc", "securityd client: active user");
                client->musr = SecMUSRCreateActiveUserUUID(client->activeUser);
                client->uid = (uid_t)client->activeUser;
                client->keybag = KEYBAG_DEVICE;
            }
        } else
#endif /* KEYCHAIN_SUPPORTS_EDU_MODE_MULTIUSER && HAVE_MOBILE_KEYBAG_SUPPORT */
#if KEYCHAIN_SUPPORTS_PERSONA_MULTIUSER
        {
            SecFillSecurityClientMuser(client);
        }
#endif /* KEYCHAIN_SUPPORTS_PERSONA_MULTIUSER */

        client->task = SecTaskCreateWithAuditToken(kCFAllocatorDefault, auditToken);
        client->accessGroups = SecTaskCopyAccessGroups(client->task);
        client->applicationIdentifier = SecTaskCopyApplicationIdentifier(client->task);
        client->isAppClip = SecTaskGetBooleanValueForEntitlement(client->task, kSystemEntitlementOnDemandInstallCapable);
        if (client->isAppClip) {
            secinfo("serverxpc", "securityd client: app clip (API restricted)");
        }
        client->allowKeychainSharing = SecTaskGetBooleanValueForEntitlement(client->task, kSecEntitlementPrivateKCSharingClient);

#if KEYCHAIN_SUPPORTS_SYSTEM_KEYCHAIN
#if TARGET_OS_TV
        client->allowSystemKeychain = true;
#else
        client->allowSystemKeychain = SecTaskGetBooleanValueForEntitlement(client->task, kSecEntitlementPrivateSystemKeychain);
#endif
#endif
#if TARGET_OS_IPHONE
        client->isNetworkExtension = SecTaskGetBooleanValueForEntitlement(client->task, kSecEntitlementPrivateNetworkExtension);
        client->canAccessNetworkExtensionAccessGroups = SecTaskGetBooleanValueForEntitlement(client->task, kSecEntitlementNetworkExtensionAccessGroups);
#endif
#if HAVE_MOBILE_KEYBAG_SUPPORT && KEYCHAIN_SUPPORTS_EDU_MODE_MULTIUSER
        if (client->inEduMode) {
            client->allowSyncBubbleKeychain = SecTaskGetBooleanValueForEntitlement(client->task, kSecEntitlementPrivateKeychainSyncBubble);
        }
#endif
        if (!securityCheckClientAccessGroups(client)) {
            CFReleaseNull(client->task);
            CFReleaseNull(client->accessGroups);
            CFReleaseNull(client->musr);
            CFReleaseNull(client->applicationIdentifier);
            return false;
        }
    }
    return true;
}

// Stolen and adapted from securityd_service
bool SecTaskIsEligiblePlatformBinary(SecTaskRef task, CFArrayRef identifiers) {
#if (DEBUG || RC_BUILDIT_YES)
    secnotice("serverxpc", "Accepting client because debug");
    return true;
#else

    if (task == NULL) {
        secerror("serverxpc: Client task is null, cannot verify platformness");
        return false;
    }

    uint32_t flags = SecTaskGetCodeSignStatus(task);
    /* check if valid and platform binary, but not platform path */

    if ((flags & (CS_VALID | CS_PLATFORM_BINARY | CS_PLATFORM_PATH)) != (CS_VALID | CS_PLATFORM_BINARY)) {
        if (SecIsInternalRelease()) {
            if ((flags & (CS_DEBUGGED | CS_PLATFORM_BINARY | CS_PLATFORM_PATH)) != (CS_DEBUGGED | CS_PLATFORM_BINARY)) {
                secerror("serverxpc: client is not a platform binary: 0x%08x", flags);
                return false;
            }
        } else {
            secerror("serverxpc: client is not a platform binary: 0x%08x", flags);
            return false;
        }
    }

    CFStringRef signingIdentifier = SecTaskCopySigningIdentifier(task, NULL);
    if (identifiers) {
        if (signingIdentifier == NULL) {
            secerror("serverxpc: client has no codesign identifier");
            return false;
        }

        __block bool result = false;
        CFArrayForEach(identifiers, ^(const void *value) {
            if (CFEqual(value, signingIdentifier)) {
                result = true;
            }
        });

        if (result == true) {
            secinfo("serverxpc", "client %@ is eligible platform binary", signingIdentifier);
        } else {
            secerror("serverxpc: client %@ is not eligible", signingIdentifier);
        }

        CFReleaseNull(signingIdentifier);
        return result;
    }

    secinfo("serverxpc", "Client %@ is valid platform binary", signingIdentifier);
    CFReleaseNull(signingIdentifier);
    return true;

#endif
}
