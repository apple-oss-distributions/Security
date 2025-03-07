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

/*
 * SecTrustOSXEntryPoints - Interface for unified SecTrust into OS X Security
 * Framework.
 */

#include "trust/trustd/macOS/SecTrustOSXEntryPoints.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dispatch/dispatch.h>
#include <notify.h>

#include <Security/Security.h>
#include <Security/SecItemPriv.h>
#include <Security/SecTrustSettingsPriv.h>
#include <Security/SecItemInternal.h>

void SecTrustLegacySourcesListenForKeychainEvents(void) {
    /* Register for CertificateTrustNotification */
    int out_token = 0;
    notify_register_dispatch(kSecServerCertificateTrustNotification, &out_token,
                             dispatch_get_main_queue(),
                             ^(int token __unused) {
        // Purge keychain parent cache
        SecItemParentCachePurge();
        // Purge trust settings cert cache
        SecTrustSettingsPurgeUserAdminCertsCache();
        // Purge the trust settings cache
        SecTrustSettingsPurgeCache();
    });
}
