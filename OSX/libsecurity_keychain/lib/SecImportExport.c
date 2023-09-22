/*
 * Copyright (c) 2007-2014 Apple Inc. All Rights Reserved.
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
#include <Security/SecBasePriv.h>
#include <Security/SecItem.h>
#include <Security/SecCertificate.h>
#include <Security/SecCertificatePriv.h>
#include <Security/SecIdentity.h>
#include <Security/SecIdentityPriv.h>
#include <Security/SecPolicy.h>
#include <Security/SecTrust.h>
#include <Security/SecKeyPriv.h>
#include <Security/SecInternal.h>
#import "debugging.h"

//#include <AssertMacros.h>
#include <CommonCrypto/CommonDigest.h>

//#include "p12import.h"
#include <Security/SecImportExportPriv.h>

#include <CoreFoundation/CFPriv.h>

const CFStringRef __nonnull kSecImportExportPassphrase = CFSTR("passphrase");
const CFStringRef __nonnull kSecImportExportKeychain = CFSTR("keychain");
const CFStringRef __nonnull kSecImportExportAccess = CFSTR("access");

const CFStringRef __nonnull kSecImportItemLabel = CFSTR("label");
const CFStringRef __nonnull kSecImportItemKeyID = CFSTR("keyid");
const CFStringRef __nonnull kSecImportItemTrust = CFSTR("trust");
const CFStringRef __nonnull kSecImportItemCertChain = CFSTR("chain");
const CFStringRef __nonnull kSecImportItemIdentity = CFSTR("identity");

#if 0
static void collect_certs(const void *key, const void *value, void *context)
{
    if (!CFDictionaryContainsKey(value, CFSTR("key"))) {
        CFDataRef cert_bytes = CFDictionaryGetValue(value, CFSTR("cert"));
        if (!cert_bytes)
            return;
        SecCertificateRef cert =
            SecCertificateCreateWithData(kCFAllocatorDefault, cert_bytes);
        if (!cert)
            return;
        CFMutableArrayRef cert_array = (CFMutableArrayRef)context;
        CFArrayAppendValue(cert_array, cert);
        CFRelease(cert);
    }
}

typedef struct {
    CFMutableArrayRef identities;
    CFArrayRef certs;
} build_trust_chains_context;

static void build_trust_chains(const void *key, const void *value,
    void *context)
{
    CFMutableDictionaryRef identity_dict = CFDictionaryCreateMutable(kCFAllocatorDefault,
        0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    SecKeyRef private_key = NULL;
    SecCertificateRef cert = NULL;
    SecIdentityRef identity = NULL;
    SecPolicyRef policy = NULL;
    CFMutableArrayRef cert_chain = NULL, eval_chain = NULL;
    SecTrustRef trust = NULL;
    build_trust_chains_context * a_build_trust_chains_context = (build_trust_chains_context*)context;

    CFDataRef key_bytes = CFDictionaryGetValue(value, CFSTR("key"));
	if(!key_bytes) goto out; //require(key_bytes, out);
    CFDataRef cert_bytes = CFDictionaryGetValue(value, CFSTR("cert"));
    if(!cert_bytes) goto out; //require(cert_bytes, out);

    /* p12import only passes up rsa keys */
//FIXME: needs SecKeyCreateRSAPrivateKey implementation
//#if 0
//	private_key = SecKeyCreateRSAPrivateKey(kCFAllocatorDefault,
//        CFDataGetBytePtr(key_bytes), CFDataGetLength(key_bytes),
//        kSecKeyEncodingPkcs1);
//#endif
    if(!private_key) goto out; //require(private_key, out);
    cert = SecCertificateCreateWithData(kCFAllocatorDefault, cert_bytes);
	if(!cert) goto out; //require(cert, out);
    identity = SecIdentityCreate(kCFAllocatorDefault, cert, private_key);
	if(!identity) goto out; //require(identity, out);
    CFDictionarySetValue(identity_dict, kSecImportItemIdentity, identity);

    eval_chain = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	if(!eval_chain) goto out; //require(eval_chain, out);
    CFArrayAppendValue(eval_chain, cert);
    CFRange all_certs = { 0, CFArrayGetCount(a_build_trust_chains_context->certs) };
    CFArrayAppendArray(eval_chain, a_build_trust_chains_context->certs, all_certs);
    policy = SecPolicyCreateBasicX509();
	if(!policy) goto out; //require(policy, out);
    SecTrustResultType result;
    SecTrustCreateWithCertificates(eval_chain, policy, &trust);
	if(!trust) goto out; //require(trust, out);
    SecTrustEvaluate(trust, &result);
    CFDictionarySetValue(identity_dict, kSecImportItemTrust, trust);

    cert_chain = SecTrustCopyCertificateChain(trust);
	if(!cert_chain) goto out; //require(cert_chain, out);
    CFDictionarySetValue(identity_dict, kSecImportItemCertChain, cert_chain);

    CFArrayAppendValue(a_build_trust_chains_context->identities, identity_dict);
out:
    CFReleaseSafe(identity_dict);
    CFReleaseSafe(identity);
    CFReleaseSafe(private_key);
    CFReleaseSafe(cert);
    CFReleaseSafe(policy);
    CFReleaseSafe(cert_chain);
    CFReleaseSafe(eval_chain);
    CFReleaseSafe(trust);
}
#endif // if 0

static void parsePkcs12itemsAndAddtoModernKeychain(const void *value, void *context)
{
    OSStatus status = errSecSuccess;
    CFDictionaryRef options = (CFDictionaryRef)context;
    CFBooleanRef sync = kCFBooleanFalse;
    if (options && CFDictionaryGetValue(options, kSecAttrSynchronizable)) {
        sync = kCFBooleanTrue;
    }
    if (CFGetTypeID(value) == CFDictionaryGetTypeID())
    {
        CFDictionaryRef item = (CFDictionaryRef)value;
        if (CFDictionaryContainsKey(item, kSecImportItemIdentity)) {
            SecIdentityRef identity = (SecIdentityRef)CFDictionaryGetValue(item, kSecImportItemIdentity);
            CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                     0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            CFDictionaryAddValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
            CFDictionaryAddValue(query, kSecAttrSynchronizable, sync);
            CFDictionaryAddValue(query, kSecClass, kSecClassIdentity);
            CFDictionaryAddValue(query, kSecValueRef, identity);
            status = SecItemAdd(query, NULL);
            switch(status) {
                case errSecSuccess:
                    secnotice("p12Decode", "cert added to keychain");
                    break;
                case errSecDuplicateItem:    // dup cert, OK to skip
                    secnotice("p12Decode", "skipping dup cert");
                    break;
                default: //all other errors
                    secerror("p12Decode: Error %d adding identity to keychain", status);
            }
            CFReleaseNull(query);
        }
        if (CFDictionaryContainsKey(item, kSecImportItemCertChain)) {
            //go through certificate chain and all certificates
            CFArrayRef certChain = (CFArrayRef)CFDictionaryGetValue(item, kSecImportItemCertChain);
            for (unsigned index=0; index<CFArrayGetCount(certChain); index++) {
                SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certChain, index);
                CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                         0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                CFDictionaryAddValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
                CFDictionaryAddValue(query, kSecAttrSynchronizable, sync);
                CFDictionaryAddValue(query, kSecClass, kSecClassCertificate);
                CFDictionaryAddValue(query, kSecValueRef, cert);
                status = SecItemAdd(query, NULL);
                switch(status) {
                    case errSecSuccess:
                        secnotice("p12Decode", "cert added to keychain");
                        break;
                    case errSecDuplicateItem:    // dup cert, OK to skip
                        secnotice("p12Decode", "skipping dup cert");
                        break;
                    default: //all other errors
                        secerror("p12Decode: Error %d adding identity to keychain", status);
                }
                CFReleaseNull(query);
            }
        }
    }
}

static OSStatus SecPKCS12Import_ios_wrapper(CFDataRef pkcs12_data, CFDictionaryRef options, CFArrayRef *items)
{
    OSStatus status = errSecSuccess;
    //Decode the pkcs12 data into array of items
    status = SecPKCS12Import_ios(pkcs12_data, options, items);

    if (status == errSecSuccess) {
        //items is an array of dictionary containing kSecImportItemIdentity,kSecImportItemCertChain
        //kSecImportItemTrust keys/value pairs.
        CFRange range = CFRangeMake(0, CFArrayGetCount(*items));
        CFArrayApplyFunction(*items, range, parsePkcs12itemsAndAddtoModernKeychain, (void*)options);
    }
    return status;
}

OSStatus SecPKCS12Import(CFDataRef pkcs12_data, CFDictionaryRef options, CFArrayRef *items)
{
	if (_CFMZEnabled()) {
		return SecPKCS12Import_ios(pkcs12_data, options, items);
	}
	// SecPKCS12Import is implemented on Mac OS X in terms of the existing
	// SecKeychainItemImport API, which supports importing items into a
	// specified keychain with initial access control settings for keys.
	//
	OSStatus status = errSecSuccess;
	SecExternalFormat inputFormat = kSecFormatPKCS12;
	SecExternalItemType itemType = kSecItemTypeAggregate;
	SecItemImportExportFlags flags = 0; /* don't know if it's PEM armoured */
	SecKeyImportExportParameters keyParams; /* filled in below... */
	SecKeychainRef importKeychain = NULL;
	SecAccessRef importAccess = NULL;
	CFStringRef importPassword = NULL;
	CFArrayRef tmpItems = NULL; /* items returned by SecKeychainItemImport */
	CFMutableArrayRef certs = NULL; /* certificates imported by this function */
	CFMutableArrayRef identities = NULL; /* items returned by this function */

	if (options) {
        CFBooleanRef dataProtectionEnabled = CFDictionaryGetValue(options, kSecUseDataProtectionKeychain);
        if (dataProtectionEnabled) {
            return SecPKCS12Import_ios_wrapper(pkcs12_data, options, items);
        }
		importKeychain = (SecKeychainRef) CFDictionaryGetValue(options, kSecImportExportKeychain);
		if (importKeychain)
			CFRetain(importKeychain);
		importAccess = (SecAccessRef) CFDictionaryGetValue(options, kSecImportExportAccess);
		if (importAccess)
			CFRetain(importAccess);
		importPassword = (CFStringRef) CFDictionaryGetValue(options, kSecImportExportPassphrase);
		if (importPassword)
			CFRetain(importPassword);
	}

	if (!importKeychain) {
		// SecKeychainItemImport requires a keychain, so use default
		status = SecKeychainCopyDefault(&importKeychain);
	}

	memset(&keyParams, 0, sizeof(SecKeyImportExportParameters));
	keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
	keyParams.passphrase = importPassword;
	keyParams.accessRef = importAccess;

	status = SecKeychainItemImport(pkcs12_data,
								   NULL,		/* no filename */
								   &inputFormat,
								   &itemType,
								   flags,
								   &keyParams,
								   importKeychain,
								   &tmpItems);

	// build an array of all non-identity certificates which were imported
	if (!status) {
		certs = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
		CFIndex i, count = CFArrayGetCount(tmpItems);
		for (i=0; i<count; i++) {
			CFTypeRef anItem = (CFTypeRef)CFArrayGetValueAtIndex(tmpItems, i);
			CFTypeID itemID = CFGetTypeID(anItem);
			if (itemID == SecCertificateGetTypeID()) {
				CFArrayAppendValue(certs, anItem);
			}
		}
	}

	// now build the output items (array of dictionaries)
	if (!status) {
		identities = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
		CFIndex i, count = CFArrayGetCount(tmpItems);
		for (i=0; i<count; i++) {
			CFTypeRef anItem = (CFTypeRef)CFArrayGetValueAtIndex(tmpItems, i);
			CFTypeID itemID = CFGetTypeID(anItem);
			if (itemID == SecIdentityGetTypeID()) {
				CFMutableDictionaryRef itemDict;
				itemDict = CFDictionaryCreateMutable(kCFAllocatorDefault,
													 0,
													 &kCFTypeDictionaryKeyCallBacks,
													 &kCFTypeDictionaryValueCallBacks);

				SecCertificateRef itemCert = NULL;
				status = SecIdentityCopyCertificate((SecIdentityRef)anItem, &itemCert);

				// label
				if (!status) {
					CFStringRef label = SecCertificateCopySubjectSummary(itemCert);
					if (label) {
						CFDictionaryAddValue(itemDict, kSecImportItemLabel, label);
						CFRelease(label);
					}
				}

				// key ID
				if (!status) {
					CFDataRef digest = SecCertificateCopyPublicKeySHA1Digest(itemCert);
					if (digest) {
						CFDictionaryAddValue(itemDict, kSecImportItemKeyID, digest);
						CFRelease(digest);
					}
				}

				// trust
				SecTrustRef trust = NULL;
				SecPolicyRef policy = SecPolicyCreateBasicX509();
				CFMutableArrayRef certArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
				CFArrayAppendValue(certArray, itemCert);
				if (certs) {
					CFArrayAppendArray(certArray, certs, CFRangeMake(0, CFArrayGetCount(certs)));
				}
				status = SecTrustCreateWithCertificates(certArray, policy, &trust);
				if (policy) {
					CFRelease(policy);
				}
				if (trust) {
					CFDictionaryAddValue(itemDict, kSecImportItemTrust, trust);
					CFRelease(trust);
				}

				// certificate chain
				if (certArray) {
					CFDictionaryAddValue(itemDict, kSecImportItemCertChain, certArray);
					CFRelease(certArray);
				}

				// identity
				CFDictionaryAddValue(itemDict, kSecImportItemIdentity, anItem);

				if (itemCert)
					CFRelease(itemCert);
				CFArrayAppendValue(identities, itemDict);
				CFRelease(itemDict);
			}
		}
	}

	if (items)
		*items = identities;
	else if (identities)
		CFRelease(identities);

	if (certs)
		CFRelease(certs);
	if (tmpItems)
		CFRelease(tmpItems);
	if (importKeychain)
		CFRelease(importKeychain);
	if (importAccess)
		CFRelease(importAccess);
	if (importPassword)
		CFRelease(importPassword);

	return status;

//FIXME: needs SecAsn1Coder implementation
#if 0
    pkcs12_context context = {};
    SecAsn1CoderCreate(&context.coder);
    if (options)
        context.passphrase = CFDictionaryGetValue(options, kSecImportExportPassphrase);
    context.items = CFDictionaryCreateMutable(kCFAllocatorDefault,
        0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int status = p12decode(&context, pkcs12_data);
    if (!status) {
        CFMutableArrayRef certs = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        CFDictionaryApplyFunction(context.items, collect_certs, certs);

        CFMutableArrayRef identities = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        build_trust_chains_context a_build_trust_chains_context = { identities, certs };
        CFDictionaryApplyFunction(context.items, build_trust_chains, &a_build_trust_chains_context);
        CFReleaseSafe(certs);

        /* ignoring certs that weren't picked up as part of the certchain for found keys */

        *items = identities;
    }

    CFReleaseSafe(context.items);
    SecAsn1CoderRelease(context.coder);

    switch (status) {
    case p12_noErr: return errSecSuccess;
    case p12_passwordErr: return errSecAuthFailed;
    case p12_decodeErr: return errSecDecode;
    default: return errSecInternal;
    };
    return errSecSuccess;
#endif
}

