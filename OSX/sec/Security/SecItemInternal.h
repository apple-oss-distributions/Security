/*
 * Copyright (c) 2009,2012-2014 Apple Inc. All Rights Reserved.
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

/*!
    @header SecItemInternal
    SecItemInternal defines SPI functions dealing with persistent refs
*/

#ifndef _SECURITY_SECITEMINTERNAL_H_
#define _SECURITY_SECITEMINTERNAL_H_

#include <CoreFoundation/CFData.h>
#include <sqlite3.h>
#include <ipc/securityd_client.h>

__BEGIN_DECLS

#define kSecServerKeychainChangedNotification   "com.apple.security.keychainchanged"
#define kSecServerCertificateTrustNotification  "com.apple.security.certificatetrust"
#define kSecServerSharedItemsChangedNotification "com.apple.security.shared-items-changed"

/* label when certificate data is joined with key data */
static const CFStringRef kSecAttrIdentityCertificateData = CFSTR("certdata");
static const CFStringRef kSecAttrIdentityCertificateTokenID = CFSTR("certtkid");

// Keys for dictionary of kSecvalueData of token-based items.
static const CFStringRef kSecTokenValueObjectIDKey = CFSTR("oid");
static const CFStringRef kSecTokenValueAccessControlKey = CFSTR("ac");
static const CFStringRef kSecTokenValueDataKey = CFSTR("data");

CFDataRef _SecItemCreatePersistentRef(CFTypeRef iclass, sqlite_int64 rowid, CFDictionaryRef attributes);
CFDataRef _SecItemCreateUUIDBasedPersistentRef(CFTypeRef iclass, CFDataRef uuidData, CFDictionaryRef attributes);

bool _SecItemParsePersistentRef(CFDataRef persistent_ref, CFStringRef *return_class,
    sqlite_int64 *return_rowid, CFDataRef *return_uuid, CFDictionaryRef *return_token_attrs);

OSStatus _SecRestoreKeychain(const char *path);

OSStatus SecOSStatusWith(bool (^perform)(CFErrorRef *error));

bool cftype_client_to_bool_cftype_error_request(enum SecXPCOperation op, CFTypeRef attributes, __unused SecurityClient *client, CFTypeRef *result, CFErrorRef *error);

/* Structure representing copy-on-write dictionary.  Typical use is:
 int bar(CFDictionaryRef input);
 int foo(CFDictionaryRef input) {
     SecCFDictionaryCOW in = { input };
     if (condition) {
         CFDictionarySetValue(SecCFDictionaryCOWGetMutable(&in), key, value);
     }
     bar(in.dictionary);
     CFReleaseSafe(in.mutable_dictionary);
 }
 */
typedef struct {
    // Real dictionary, not owned by this structure, should be accessed directly for read-only access.
    CFDictionaryRef dictionary;

    // On-demand created (and possibly modified), owned writable copy of dictionary.
    CFMutableDictionaryRef mutable_dictionary;
} SecCFDictionaryCOW;

CFMutableDictionaryRef SecCFDictionaryCOWGetMutable(SecCFDictionaryCOW *cow_dictionary);

typedef enum {
    kSecItemAuthResultOK,
    kSecItemAuthResultError,
    kSecItemAuthResultNeedAuth
} SecItemAuthResult;

void SecItemAuthCopyParams(SecCFDictionaryCOW *auth_params, SecCFDictionaryCOW *query);

CFDictionaryRef SecTokenItemValueCopy(CFDataRef db_value, CFErrorRef *error);

CFArrayRef SecItemCopyParentCertificates_ios(CFDataRef normalizedIssuer, CFArrayRef accessGroups, CFErrorRef *error);

bool SecItemCertificateExists(CFDataRef normalizedIssuer, CFDataRef serialNumber, CFArrayRef accessGroups, CFErrorRef *error);

/*!
    @constant kSecAttrAppClipItem Boolean attribute indicating whether the origin of this item is an App Clip client
*/
static const CFStringRef kSecAttrAppClipItem = CFSTR("clip");

__END_DECLS

#endif /* !_SECURITY_SECITEMINTERNAL_H_ */
