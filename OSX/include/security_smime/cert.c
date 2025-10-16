/*
 * Copyright (c) 2003,2011-2012,2014 Apple Inc. All Rights Reserved.
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


#include "cert.h"
#include <Security/SecCertificatePriv.h>
#include <Security/SecIdentity.h>
#include <Security/SecIdentityPriv.h>
#include <Security/SecIdentitySearch.h>
#include <Security/SecItem.h>
#include <Security/SecKeychain.h>
#include <Security/SecKeychainItem.h>
#include <Security/SecKeychainSearch.h>
#include <Security/SecPolicyPriv.h>
#include <Security/cssmapi.h>
#include <Security/oidsalg.h>
#include <Security/oidscert.h>
#include <security_asn1/secerr.h>
#include <syslog.h>
#include <utilities/SecCFWrappers.h>
#include "cmslocal.h"
#include "cmstpriv.h"
#include "secitem.h"

/* for errKCDuplicateItem */
#include <CoreServices/../Frameworks/CarbonCore.framework/Headers/MacErrors.h>

#define CERT_DEBUG 0
#if CERT_DEBUG
#define dprintf(args...) fprintf(stderr, args)
#else
#define dprintf(args...)
#endif

/* 
 * Normalize a Printable String. Per RFC2459 (4.1.2.4), printable strings are case 
 * insensitive and we're supposed to ignore leading and trailing 
 * whitespace, and collapse multiple whitespace characters into one. 
 */
static void CERT_NormalizeString(CSSM_DATA_PTR string)
{
    char *pD, *pCh, *pEos;

    if (!string->Length) {
        return;
    }

    pD = pCh = (char*)string->Data;
    pEos = pCh + string->Length - 1;

    /* Strip trailing NULL terminators */
    while (*pEos == 0) {
        pEos--;
    }

    /* Remove trailing spaces */
    while (isspace(*pEos)) {
        pEos--;
    }

    /* Point to one past last non-space character */
    pEos++;

    /* skip all leading whitespace */
    while (isspace(*pCh) && (pCh < pEos)) {
        pCh++;
    }

    /* Eliminate multiple whitespace and convent to upper case.
     * pCh points to first non-white char.
     * pD still points to start of string. */
    while (pCh < pEos) {
        char ch = *pCh++;
        *pD++ = toupper(ch);
        if (isspace(ch)) {
            /* skip 'til next nonwhite */
            while (isspace(*pCh) && (pCh < pEos)) {
                pCh++;
            }
        }
    }

    if (pD >= (char *)string->Data) {
        string->Length = (size_t)(pD - (char*)string->Data);
    } else {
        string->Length = 0;
    }
}

/* 
 * Normalize an RDN. Per RFC2459 (4.1.2.4), printable strings are case 
 * insensitive and we're supposed to ignore leading and trailing 
 * whitespace, and collapse multiple whitespace characters into one. 
 *
 * Incoming NSS_Name is assumed to be entirely within specifed coder's
 * address space; we'll be munging some of that and possibly replacing
 * some pointers with others allocated from the same space. 
 */
void CERT_NormalizeX509NameNSS(NSS_Name* nssName)
{
    NSS_RDN* rdn;

    for (rdn = *nssName->rdns; rdn; ++rdn) {
        NSS_ATV* attr;
        for (attr = *rdn->atvs; attr; ++attr) {
            /* 
		* attr->value is an ASN_ANY containing an encoded
		* string. We only normalize Prinatable String types. 
		* If we find one, decode it, normalize it, encode the
		* result, and put the encoding back in attr->value.
		* We temporarily "leak" the original string, which only
		* has a lifetime of the incoming SecNssCoder. 
		*/
            NSS_TaggedItem* attrVal = &attr->value;
            if (attrVal->tag != SEC_ASN1_PRINTABLE_STRING)
                continue;

            CERT_NormalizeString(&attrVal->item);
        }
    }
}

static bool
_is_apple_mail_bundle(void)
{
    static dispatch_once_t onceToken;
    static bool result = false;
    dispatch_once(&onceToken, ^{
        CFBundleRef bundle = CFBundleGetMainBundle();
        if (bundle) {
            CFStringRef bundleID = CFBundleGetIdentifier(bundle);
            result = (bundleID != NULL) && (CFStringHasPrefix(bundleID, CFSTR("com.apple.mail"))
                                            || CFStringHasPrefix(bundleID, CFSTR("com.apple.mobilemail"))
                                            || CFStringHasPrefix(bundleID, CFSTR("com.apple.email")));
        }
    });
    return result;
}

static OSStatus
_SecCertificateFindByEmail(CFTypeRef keychainOrArray, const char *emailAddress, SecCertificateRef *certificate)
{
    if (_is_apple_mail_bundle() && emailAddress) {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny);

        CFStringRef emailAddressString = CFStringCreateWithCString(kCFAllocatorDefault, emailAddress, kCFStringEncodingUTF8);
        CFTypeRef keys[] = { kSecPolicyName };
        CFTypeRef values[] = { emailAddressString };
        CFDictionaryRef properties = CFDictionaryCreate(kCFAllocatorDefault, keys, values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        SecPolicyRef policy = SecPolicyCreateWithProperties(kSecPolicyAppleSMIME, properties);
        CFDictionarySetValue(query, kSecMatchPolicy, policy);

        OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)certificate);

        CFReleaseNull(policy);
        CFReleaseNull(properties);
        CFReleaseNull(emailAddressString);
        CFReleaseNull(query);

        if (status == errSecSuccess) {
            return status;
        }
    }

    return SecCertificateFindByEmail(keychainOrArray, emailAddress, certificate);
}

SecCertificateRef CERT_FindCertByNicknameOrEmailAddr(SecKeychainRef keychainOrArray, char* name)
{
    SecCertificateRef certificate;
    OSStatus status = _SecCertificateFindByEmail(keychainOrArray, name, &certificate);
    return status == noErr ? certificate : NULL;
}

SecPublicKeyRef SECKEY_CopyPublicKey(SecPublicKeyRef pubKey)
{
    CFRetain(pubKey);
    return pubKey;
}

void SECKEY_DestroyPublicKey(SecPublicKeyRef pubKey)
{
    CFReleaseNull(pubKey);
}

SecPublicKeyRef SECKEY_CopyPrivateKey(SecPublicKeyRef privKey)
{
    CFRetainSafe(privKey);
    return privKey;
}

void SECKEY_DestroyPrivateKey(SecPublicKeyRef privKey)
{
    CFReleaseNull(privKey);
}

void CERT_DestroyCertificate(SecCertificateRef cert)
{
    CFReleaseNull(cert);
}

SecCertificateRef CERT_DupCertificate(SecCertificateRef cert)
{
    CFRetainSafe(cert);
    return cert;
}

static OSStatus
_SecIdentityFindByIssuerAndSN(SecCertificateRef certificate, SecIdentityRef *ident)
{
    OSStatus status = errSecItemNotFound;

    CFMutableDictionaryRef query = NULL;
    CFDataRef issuerData = NULL;
    CFDataRef serialNumberData = NULL;
    CFTypeRef item = NULL;

    if (certificate) {
        issuerData = SecCertificateCopyIssuerSequence(certificate);
        serialNumberData = SecCertificateCopySerialNumberData(certificate, NULL);
    }

    if (issuerData && serialNumberData) {
        query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(query, kSecClass, kSecClassIdentity);
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny);
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);

        CFDictionarySetValue(query, kSecAttrIssuer, issuerData);
        CFDictionarySetValue(query, kSecAttrSerialNumber, serialNumberData);

        status = SecItemCopyMatching(query, &item);
        if (status == errSecSuccess && ident != NULL) {
            *ident = (SecIdentityRef)item;
        }
    }

    CFReleaseNull(serialNumberData);
    CFReleaseNull(issuerData);
    CFReleaseNull(query);

    return status;
}

SecIdentityRef CERT_FindIdentityByUsage(SecKeychainRef keychainOrArray,
                                        char* nickname,
                                        SECCertUsage usage,
                                        Boolean validOnly,
                                        void* proto_win)
{
    SecIdentityRef identityRef = NULL;
    SecCertificateRef cert = CERT_FindCertByNicknameOrEmailAddr(keychainOrArray, nickname);
    if (!cert) {
        return NULL;
    }

    if (_is_apple_mail_bundle()) {
        SecIdentityRef item;
        OSStatus status = _SecIdentityFindByIssuerAndSN(cert, &item);
        if (status == errSecSuccess) {
            identityRef = item;
        }
    }

    if (identityRef == NULL) {
        SecIdentityCreateWithCertificate(keychainOrArray, cert, &identityRef);
    }

    CFReleaseNull(cert);

    return identityRef;
}

SecCertificateRef CERT_FindUserCertByUsage(SecKeychainRef keychainOrArray,
                                           char* nickname,
                                           SECCertUsage usage,
                                           Boolean validOnly,
                                           void* proto_win)
{
    SecItemClass itemClass = kSecCertificateItemClass;
    SecKeychainSearchRef searchRef;
    SecKeychainItemRef itemRef = NULL;
    OSStatus status;
    SecKeychainAttribute attrs[1];
    const char* serialNumber = "12345678";
    //   const SecKeychainAttributeList attrList;
#if 0
    attrs[0].tag = kSecLabelItemAttr;
    attrs[0].length = strlen(nickname)+1;
    attrs[0].data = nickname;
#else
    attrs[0].tag = kSecSerialNumberItemAttr;
    attrs[0].length = (UInt32)strlen(serialNumber) + 1;
    attrs[0].data = (uint8*)serialNumber;
#endif
    SecKeychainAttributeList attrList = {0, attrs};
    //   12 34 56 78
    status = SecKeychainSearchCreateFromAttributes(keychainOrArray, itemClass, &attrList, &searchRef);
    if (status) {
        printf("CERT_FindUserCertByUsage: SecKeychainSearchCreateFromAttributes:%d", (int)status);
        return NULL;
    }
    status = SecKeychainSearchCopyNext(searchRef, &itemRef);
    if (status) {
        printf("CERT_FindUserCertByUsage: SecKeychainSearchCopyNext:%d", (int)status);
    }
    CFReleaseNull(searchRef);
    return (SecCertificateRef)itemRef;
}

/*
startNewClass(X509Certificate)
CertType, kSecCertTypeItemAttr, "CertType", 0, NULL, UINT32)
CertEncoding, kSecCertEncodingItemAttr, "CertEncoding", 0, NULL, UINT32)
PrintName, kSecLabelItemAttr, "PrintName", 0, NULL, BLOB)
Alias, kSecAlias, "Alias", 0, NULL, BLOB)
Subject, kSecSubjectItemAttr, "Subject", 0, NULL, BLOB)
Issuer, kSecIssuerItemAttr, "Issuer", 0, NULL, BLOB)
SerialNumber, kSecSerialNumberItemAttr, "SerialNumber", 0, NULL, BLOB)
SubjectKeyIdentifier, kSecSubjectKeyIdentifierItemAttr, "SubjectKeyIdentifier", 0, NULL, BLOB)
PublicKeyHash, kSecPublicKeyHashItemAttr, "PublicKeyHash", 0, NULL, BLOB)
endNewClass()
*/

CFArrayRef CERT_CertChainFromCert(SecCertificateRef cert, SECCertUsage usage, Boolean includeRoot, Boolean mustIncludeRoot)
{
    SecPolicyRef policy = NULL;
    CFArrayRef wrappedCert = NULL;
    SecTrustRef trust = NULL;
    CFArrayRef certs = NULL;
    OSStatus status = 0;

    if (!cert) {
        goto loser;
    }

    policy = SecPolicyCreateBasicX509();
    if (!policy) {
        goto loser;
    }

    wrappedCert = CERT_CertListFromCert(cert);
    status = SecTrustCreateWithCertificates(wrappedCert, policy, &trust);
    if (status) {
        goto loser;
    }

    /* SecTrustEvaluate will build us the best chain available using its heuristics.
     * We'll ignore the trust result. */
    SecTrustResultType result;
    status = SecTrustEvaluate(trust, &result);
    if (status) {
        goto loser;
    }
    certs = SecTrustCopyCertificateChain(trust);
    CFIndex count = certs ? CFArrayGetCount(certs) : 0;

    /* If we weren't able to build a chain to a self-signed cert, warn. */
    Boolean isSelfSigned = false;
    SecCertificateRef lastCert = certs ? (SecCertificateRef)CFArrayGetValueAtIndex(certs, count - 1) : NULL;
    if (lastCert && (0 == SecCertificateIsSelfSigned(lastCert, &isSelfSigned)) && !isSelfSigned) {
        CFStringRef commonName = NULL;
        (void)SecCertificateCopyCommonName(cert, &commonName);
        fprintf(stderr,
                "Warning: unable to build chain to self-signed root for signer \"%s\"\n",
                commonName ? CFStringGetCStringPtr(commonName, kCFStringEncodingUTF8) : "");
        CFReleaseNull(commonName);

        // we don't have a root, so if the caller required one, fail
        if (mustIncludeRoot) {
            status = errSecCreateChainFailed;
        }
    }

    /* We don't drop the root if there is only 1 certificate in the chain. */
    if (isSelfSigned && !includeRoot && count > 1) {
        CFMutableArrayRef nonRootChain = CFArrayCreateMutableCopy(NULL, count, certs);
        CFArrayRemoveValueAtIndex(nonRootChain, count - 1);
        CFAssignRetained(certs, nonRootChain);
    }

loser:
    CFReleaseNull(policy);
    CFReleaseNull(wrappedCert);
    CFReleaseNull(trust);
    if (status) {
        CFReleaseNull(certs);
    }

    return certs;
}

CFArrayRef CERT_CertListFromCert(SecCertificateRef cert)
{
    const void* value = cert;
    return cert ? CFArrayCreate(NULL, &value, 1, &kCFTypeArrayCallBacks) : NULL;
}

CFArrayRef CERT_DupCertList(CFArrayRef oldList)
{
    CFRetainSafe(oldList);
    return oldList;
}

// Extract a public key object from a SubjectPublicKeyInfo
SecPublicKeyRef CERT_ExtractPublicKey(SecCertificateRef cert)
{
    return SecCertificateCopyKey(cert);
}

SECStatus CERT_CheckCertUsage(SecCertificateRef cert, unsigned char usage)
{
    // abort();
    // @@@ It's all good, it's ok.
    return SECSuccess;
}

// Find a certificate in the database by a email address
// "emailAddr" is the email address to look up
SecCertificateRef CERT_FindCertByEmailAddr(SecKeychainRef keychainOrArray, char* emailAddr)
{
    abort();
    return NULL;
}

// Find a certificate in the database by a DER encoded certificate
// "derCert" is the DER encoded certificate
SecCertificateRef CERT_FindCertByDERCert(SecKeychainRef keychainOrArray, const SECItem* derCert)
{
    // @@@ Technically this should look though keychainOrArray for a cert matching this one I guess.
    SecCertificateRef cert = NULL;
    OSStatus rv;

    rv = SecCertificateCreateFromData(derCert, CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &cert);
    if (rv && cert) {
        PORT_SetError(SEC_ERROR_NO_EMAIL_CERT);
        CFReleaseNull(cert);
    }

    return cert;
}

int CERT_CompareCssmData(const CSSM_DATA* d1, const CSSM_DATA* d2)
{
    if ((d1 == NULL) || (d2 == NULL)) {
        return 0;
    }
    if (d1->Length != d2->Length) {
        return 0;
    }
    if (memcmp(d1->Data, d2->Data, d1->Length)) {
        return 0;
    }
    return 1;
}

static OSStatus
_SecCertificateFindByIssuerAndSN(CFTypeRef keychainOrArray,const CSSM_DATA *issuer,
	const CSSM_DATA *serialNumber, SecCertificateRef *certificate)
{
    if (_is_apple_mail_bundle() && issuer && issuer->Data && issuer->Length > 0 &&
        serialNumber && serialNumber->Data && serialNumber->Length > 0) {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny);

        CFDataRef issuerData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (const UInt8 *)issuer->Data, (CFIndex)issuer->Length, kCFAllocatorNull);
        CFDictionarySetValue(query, kSecAttrIssuer, issuerData);

        CFDataRef serialNumberData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (const UInt8 *)serialNumber->Data, (CFIndex)serialNumber->Length, kCFAllocatorNull);
        CFDictionarySetValue(query, kSecAttrSerialNumber, serialNumberData);

        OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)certificate);

        CFReleaseNull(serialNumberData);
        CFReleaseNull(issuerData);
        CFReleaseNull(query);

        if (status == errSecSuccess) {
            return status;
        }
    }

    return SecCertificateFindByIssuerAndSN(keychainOrArray, issuer, serialNumber, certificate);
}

// Generate a certificate key from the issuer and serialnumber, then look it up in the database.
// Return the cert if found. "issuerAndSN" is the issuer and serial number to look for
SecCertificateRef CERT_FindCertByIssuerAndSN(CFTypeRef keychainOrArray,
                                             CSSM_DATA_PTR* rawCerts,
                                             CFArrayRef certList,
                                             PRArenaPool* pl,
                                             const SecCmsIssuerAndSN* issuerAndSN)
{
    SecCertificateRef certificate = NULL;
    int numRawCerts = SecCmsArrayCount((void**)rawCerts);
    int dex;
    OSStatus ortn;

    /* 
     * First search the rawCerts array.
     */
    for (dex = 0; dex < numRawCerts; dex++) {
        ortn = SecCertificateCreateFromData(
            rawCerts[dex], CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &certificate);
        if (ortn) {
            continue;
        }
        SecCmsIssuerAndSN* isn = CERT_GetCertIssuerAndSN(pl, certificate);
        if (isn == NULL) {
            CFReleaseNull(certificate);
            continue;
        }
        if (!CERT_CompareCssmData(&isn->derIssuer, &issuerAndSN->derIssuer)) {
            CFReleaseNull(certificate);
            continue;
        }
        if (!CERT_CompareCssmData(&isn->serialNumber, &issuerAndSN->serialNumber)) {
            CFReleaseNull(certificate);
            continue;
        }
        /* got it */
        dprintf("CERT_FindCertByIssuerAndSN: found cert %p\n", certificate);
        return certificate;
    }

    /* Search the user-added certList */
    if (certList && CFArrayGetCount(certList)) {
        CFIndex c, count = CFArrayGetCount(certList);
        for (c = 0; c < count; c++) {
            SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certList, c);
            SecCmsIssuerAndSN* isn = CERT_GetCertIssuerAndSN(pl, cert);
            if (isn == NULL) {
                continue;
            }
            if (!CERT_CompareCssmData(&isn->derIssuer, &issuerAndSN->derIssuer)) {
                continue;
            }
            if (!CERT_CompareCssmData(&isn->serialNumber, &issuerAndSN->serialNumber)) {
                continue;
            }
            certificate = CFRetainSafe(cert);
            break;
        }
        if (certificate) {
            return certificate;
        }
    }

    /* now search keychain(s) */
    OSStatus status = _SecCertificateFindByIssuerAndSN(
        keychainOrArray, &issuerAndSN->derIssuer, &issuerAndSN->serialNumber, &certificate);
    if (status) {
        PORT_SetError(SEC_ERROR_NO_EMAIL_CERT);
        certificate = NULL;
    }

    return certificate;
}

static OSStatus
_SecCertificateFindBySubjectKeyID(CFTypeRef keychainOrArray, const CSSM_DATA *subjectKeyID,
	SecCertificateRef *certificate)
{
    if (_is_apple_mail_bundle() && subjectKeyID) {
        CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(query, kSecClass, kSecClassCertificate);
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
        CFDictionarySetValue(query, kSecAttrSynchronizable, kSecAttrSynchronizableAny);

        CFDataRef subjectKeyIDData = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (const UInt8 *)subjectKeyID->Data, (CFIndex)subjectKeyID->Length, kCFAllocatorNull);
        CFDictionarySetValue(query, kSecAttrSubjectKeyID, subjectKeyIDData);

        OSStatus status = SecItemCopyMatching(query, (CFTypeRef*)certificate);

        CFReleaseNull(subjectKeyIDData);
        CFReleaseNull(query);

        if (status == errSecSuccess) {
            return status;
        }
    }

    return SecCertificateFindBySubjectKeyID(keychainOrArray, subjectKeyID, certificate);
}

SecCertificateRef CERT_FindCertBySubjectKeyID(CFTypeRef keychainOrArray,
                                              CSSM_DATA_PTR* rawCerts,
                                              CFArrayRef certList,
                                              const SECItem* subjKeyID)
{
    SecCertificateRef certificate = NULL;
    int numRawCerts = SecCmsArrayCount((void**)rawCerts);
    int dex;
    OSStatus ortn;

    if (subjKeyID->Length > LONG_MAX) {
        return NULL;
    }

    /* 
     * First search the rawCerts array.
     */
    for (dex = 0; dex < numRawCerts; dex++) {
        SECItem skid;
        int match;
        ortn = SecCertificateCreateFromData(rawCerts[dex], CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &certificate);
        if (ortn) {
            continue;
        }
        if (CERT_FindSubjectKeyIDExtension(certificate, &skid)) {
            CFReleaseNull(certificate);
            /* not present */
            continue;
        }
        match = CERT_CompareCssmData(subjKeyID, &skid);
        SECITEM_FreeItem(&skid, PR_FALSE);
        if (match) {
            /* got it */
            return certificate;
        }
        CFReleaseNull(certificate);
    }

    /* Search the user-added certList */
    if (certList && CFArrayGetCount(certList)) {
        CFDataRef subjectkeyid = CFDataCreateWithBytesNoCopy(
            kCFAllocatorDefault, subjKeyID->Data, (CFIndex)subjKeyID->Length, kCFAllocatorNull);
        CFIndex c, count = CFArrayGetCount(certList);
        for (c = 0; c < count; c++) {
            SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(certList, c);
            CFDataRef skid = (cert) ? SecCertificateGetSubjectKeyID(cert) : NULL;
            if (skid && CFEqual(skid, subjectkeyid)) {
                CFRetain(cert);
                certificate = cert;
                break;
            }
        }
        if (subjectkeyid) {
            CFReleaseNull(subjectkeyid);
        };
        if (certificate) {
            return certificate;
        }
    }

    /* now search keychain(s) */
    OSStatus status = _SecCertificateFindBySubjectKeyID(keychainOrArray, subjKeyID, &certificate);
    if (status) {
        PORT_SetError(SEC_ERROR_NO_EMAIL_CERT);
        certificate = NULL;
    }

    return certificate;
}

static SecIdentityRef CERT_FindIdentityByCertificate(CFTypeRef keychainOrArray,
                                                     SecCertificateRef CF_CONSUMED certificate)
{
    SecIdentityRef identity = NULL;
    SecIdentityCreateWithCertificate(keychainOrArray, certificate, &identity);
    if (!identity) {
        PORT_SetError(SEC_ERROR_NOT_A_RECIPIENT);
    }
    CFReleaseNull(certificate);

    return identity;
}

SecIdentityRef CERT_FindIdentityByIssuerAndSN(CFTypeRef keychainOrArray, const SecCmsIssuerAndSN* issuerAndSN)
{
    SecCertificateRef certificate =
        CERT_FindCertByIssuerAndSN(keychainOrArray, NULL, NULL, NULL, issuerAndSN);
    if (!certificate) {
        return NULL;
    }

    if (_is_apple_mail_bundle()) {
        SecIdentityRef identity;
        OSStatus status = _SecIdentityFindByIssuerAndSN(certificate, &identity);
        if (status == errSecSuccess) {
            return identity;
        }
    }

    return CERT_FindIdentityByCertificate(keychainOrArray, certificate);
}

SecIdentityRef CERT_FindIdentityBySubjectKeyID(CFTypeRef keychainOrArray, const SECItem* subjKeyID)
{
    SecCertificateRef certificate =
        CERT_FindCertBySubjectKeyID(keychainOrArray, NULL, NULL, subjKeyID);
    if (!certificate) {
        return NULL;
    }

    if (_is_apple_mail_bundle()) {
        SecIdentityRef identity;
        OSStatus status = _SecIdentityFindByIssuerAndSN(certificate, &identity);
        if (status == errSecSuccess) {
            return identity;
        }
    }

    return CERT_FindIdentityByCertificate(keychainOrArray, certificate);
}

// find the smime symmetric capabilities profile for a given cert
SECItem* CERT_FindSMimeProfile(SecCertificateRef cert)
{
    return NULL;
}

// Return the decoded value of the subjectKeyID extension. The caller should
// free up the storage allocated in retItem->data.
SECStatus CERT_FindSubjectKeyIDExtension(SecCertificateRef cert, SECItem* retItem)
{
    CSSM_DATA_PTR fieldValue = NULL;
    OSStatus ortn;
    CSSM_X509_EXTENSION* extp;
    CE_SubjectKeyID* skid;

    ortn = SecCertificateCopyFirstFieldValue(cert, &CSSMOID_SubjectKeyIdentifier, &fieldValue);
    if (ortn || (fieldValue == NULL)) {
        /* this cert doesn't have that extension */
        return SECFailure;
    }
    extp = (CSSM_X509_EXTENSION*)fieldValue->Data;
    skid = (CE_SubjectKeyID*)extp->value.parsedValue;
    retItem->Data = (uint8*)PORT_Alloc(skid->Length);
    retItem->Length = skid->Length;
    memmove(retItem->Data, skid->Data, retItem->Length);
    SecCertificateReleaseFirstFieldValue(cert, &CSSMOID_SubjectKeyIdentifier, fieldValue);
    return SECSuccess;
}

// Extract the issuer and serial number from a certificate
SecCmsIssuerAndSN* CERT_GetCertIssuerAndSN(PRArenaPool* pl, SecCertificateRef cert)
{
    SecCmsIssuerAndSN* certIssuerAndSN;

    void* mark;
    mark = PORT_ArenaMark(pl);
    CFDataRef issuer_data = SecCertificateCopyIssuerSequence(cert);
    CFDataRef serial_data = SecCertificateCopySerialNumberData(cert, NULL);
    if (!issuer_data || CFDataGetLength(issuer_data) < 0 ||
        !serial_data || CFDataGetLength(serial_data) < 0) {
        goto loser;
    }

    SecAsn1Item serialNumber = {.Length = (size_t)CFDataGetLength(serial_data),
                                .Data = (uint8_t*)CFDataGetBytePtr(serial_data)};
    SecAsn1Item issuer = {.Length = (size_t)CFDataGetLength(issuer_data),
                          .Data = (uint8_t*)CFDataGetBytePtr(issuer_data)};

    /* Allocate the SecCmsIssuerAndSN struct. */
    certIssuerAndSN = (SecCmsIssuerAndSN*)PORT_ArenaZAlloc(pl, sizeof(SecCmsIssuerAndSN));
    if (certIssuerAndSN == NULL) {
        goto loser;
    }

    /* Copy the issuer. */
    certIssuerAndSN->derIssuer.Data = (uint8_t*)PORT_ArenaAlloc(pl, issuer.Length);
    if (!certIssuerAndSN->derIssuer.Data) {
        goto loser;
    }
    PORT_Memcpy(certIssuerAndSN->derIssuer.Data, issuer.Data, issuer.Length);
    certIssuerAndSN->derIssuer.Length = issuer.Length;

    /* Copy the serialNumber. */
    certIssuerAndSN->serialNumber.Data = (uint8_t*)PORT_ArenaAlloc(pl, serialNumber.Length);
    if (!certIssuerAndSN->serialNumber.Data) {
        goto loser;
    }
    PORT_Memcpy(certIssuerAndSN->serialNumber.Data, serialNumber.Data, serialNumber.Length);
    certIssuerAndSN->serialNumber.Length = serialNumber.Length;

    CFReleaseNull(serial_data);
    CFReleaseNull(issuer_data);

    PORT_ArenaUnmark(pl, mark);
    return certIssuerAndSN;

loser:
    CFReleaseNull(serial_data);
    CFReleaseNull(issuer_data);
    PORT_ArenaRelease(pl, mark);
    PORT_SetError(SEC_INTERNAL_ONLY);

    return NULL;
}

// import a collection of certs into the temporary or permanent cert database
SECStatus CERT_ImportCerts(SecKeychainRef keychain,
                           SECCertUsage usage,
                           int ncerts,
                           SECItem** derCerts,
                           SecCertificateRef** retCerts,
                           Boolean keepCerts,
                           Boolean caOnly,
                           char* nickname)
{
    OSStatus rv = SECFailure;
    SecCertificateRef cert;
    unsigned int ci;

    // @@@ Do something with caOnly and nickname
    if (caOnly || nickname) {
        abort();
    }

    for (ci = 0; ci < ncerts; ++ci) {
        rv = SecCertificateCreateFromData(
            derCerts[ci], CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &cert);
        if (rv) {
            break;
        }
        if (keepCerts) {
            rv = SecCertificateAddToKeychain(cert, keychain);
            if (rv) {
                if (rv == errKCDuplicateItem) {
                    rv = noErr;
                } else {
                    CFReleaseNull(cert);
                    break;
                }
            }
        }

        if (retCerts) {
            // @@@ not yet
            abort();
        } else {
            CFReleaseNull(cert);
        }
    }

    return rv;
}

SECStatus CERT_SaveSMimeProfile(SecCertificateRef cert, SECItem* emailProfile, SECItem* profileTime)
{
    fprintf(stderr, "WARNING: CERT_SaveSMimeProfile unimplemented\n");
    return SECSuccess;
}

// Check the hostname to make sure that it matches the shexp that
// is given in the common name of the certificate.
SECStatus CERT_VerifyCertName(SecCertificateRef cert, const char* hostname)
{
    fprintf(stderr, "WARNING: CERT_VerifyCertName unimplemented\n");
    return SECSuccess;
}

/*
** OLD OBSOLETE FUNCTIONS with enum SECCertUsage - DO NOT USE FOR NEW CODE
** verify a certificate by checking validity times against a certain time,
** that we trust the issuer, and that the signature on the certificate is
** valid.
**	"cert" the certificate to verify
**	"checkSig" only check signatures if true
*/
SECStatus CERT_VerifyCert(SecKeychainRef keychainOrArray,
                          SecCertificateRef cert,
                          const CSSM_DATA_PTR* otherCerts, /* intermediates */
                          CFTypeRef policies,
                          CFAbsoluteTime stime,
                          SecTrustRef* trustRef)
{
    CFMutableArrayRef certificates = NULL;
    SecTrustRef trust = NULL;
    OSStatus rv;
    int numOtherCerts = SecCmsArrayCount((void**)otherCerts);
    int dex;

    /* 
     * Certs to evaluate: first the leaf - our cert - then all the rest we know
     * about. It's OK for otherCerts to contain a copy of the leaf. 
     */
    certificates = CFArrayCreateMutable(NULL, numOtherCerts + 1, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(certificates, cert);
    for (dex = 0; dex < numOtherCerts; dex++) {
        SecCertificateRef intCert;

        rv = SecCertificateCreateFromData(
            otherCerts[dex], CSSM_CERT_X_509v3, CSSM_CERT_ENCODING_DER, &intCert);
        if (rv) {
            goto loser;
        }
        CFArrayAppendValue(certificates, intCert);
        CFReleaseNull(intCert);
    }
    rv = SecTrustCreateWithCertificates(certificates, policies, &trust);
    CFReleaseNull(certificates);
    if (rv) {
        goto loser;
    }

    rv = SecTrustSetKeychains(trust, keychainOrArray);
    if (rv) {
        goto loser;
    }

    CFDateRef verifyDate = CFDateCreate(NULL, stime);
    rv = SecTrustSetVerifyDate(trust, verifyDate);
    CFReleaseNull(verifyDate);
    if (rv) {
        goto loser;
    }

    if (trustRef) {
        *trustRef = trust;
    } else {
        SecTrustResultType result;
        /* The caller doesn't want a SecTrust object, so let's evaluate it for them. */
        rv = SecTrustEvaluate(trust, &result);
        if (rv) {
            goto loser;
        }

        switch (result) {
            case kSecTrustResultProceed:
            case kSecTrustResultUnspecified:
                /* TP Verification succeeded and there was either a UserTurst entry
	       telling us to procceed, or no user trust setting was specified. */
                CFReleaseNull(trust);
                break;
            default:
                PORT_SetError(SEC_ERROR_UNTRUSTED_CERT);
                rv = SECFailure;
                goto loser;
                break;
        }
    }

    return SECSuccess;
loser:
#if 0 /* debugging */
	syslog(LOG_ERR, "CERT_VerifyCert has failed with %d (input policies and output trust follow)",
			(int)rv);
	if (policies) CFShow(policies);
	if (trust) CFShow(trust);
#endif
    CFReleaseNull(trust);
    CFReleaseNull(certificates);
    return rv;
}

CFTypeRef CERT_PolicyForCertUsage(SECCertUsage certUsage)
{
    SecPolicyRef policy = NULL;

    switch (certUsage) {
        case certUsageSSLServerWithStepUp:
        case certUsageSSLCA:
        case certUsageVerifyCA:
        case certUsageAnyCA:
            goto loser;
            break;
        case certUsageSSLClient:
            policy = SecPolicyCreateSSL(false, NULL);
            break;
        case certUsageSSLServer:
            policy = SecPolicyCreateSSL(true, NULL);
            break;
        case certUsageStatusResponder:
            policy = SecPolicyCreateOCSPSigner();
            break;
        case certUsageObjectSigner:
        case certUsageProtectedObjectSigner:
        case certUsageUserCertImport:
        case certUsageEmailSigner:
        case certUsageEmailRecipient:
            policy = SecPolicyCreateBasicX509();
            break;
        default:
            goto loser;
    }

loser:
    return policy;
}
