/*
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape security libraries.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

/*
 * CMS signerInfo methods.
 */

#include <Security/SecCmsSignerInfo.h>
#include "SecSMIMEPriv.h"

#include "cmslocal.h"

#include "SecAsn1Item.h"
#include "cert.h"
#include "cryptohi.h"
#include "secoid.h"

#include <security_asn1/secasn1.h>
#include <security_asn1/secerr.h>
#include <security_asn1/secport.h>
#include <security_asn1/SecAsn1TimeUtils.h>

#if USE_CDSA_CRYPTO
#include <Security/SecKeychain.h>
#endif

#include <CoreFoundation/CFTimeZone.h>
#include <Security/SecBasePriv.h>
#include <Security/SecCertificateInternal.h>
#include <Security/SecIdentity.h>
#include <Security/SecInternal.h>
#include <Security/SecItem.h>
#include <Security/SecKeyPriv.h>
#include <utilities/SecCFWrappers.h>

#include <libDER/asn1Types.h>

/* =============================================================================
 * SIGNERINFO
 */
SecCmsSignerInfoRef nss_cmssignerinfo_create(SecCmsSignedDataRef sigd,
                                             SecCmsSignerIDSelector type,
                                             SecCertificateRef cert,
                                             const SecAsn1Item* subjKeyID,
                                             SecPublicKeyRef pubKey,
                                             SecPrivateKeyRef signingKey,
                                             SECOidTag digestalgtag);

SecCmsSignerInfoRef SecCmsSignerInfoCreateWithSubjKeyID(SecCmsSignedDataRef sigd,
                                                        const SecAsn1Item* subjKeyID,
                                                        SecPublicKeyRef pubKey,
                                                        SecPrivateKeyRef signingKey,
                                                        SECOidTag digestalgtag)
{
    return nss_cmssignerinfo_create(
        sigd, SecCmsSignerIDSubjectKeyID, NULL, subjKeyID, pubKey, signingKey, digestalgtag);
}

SecCmsSignerInfoRef SecCmsSignerInfoCreate(SecCmsSignedDataRef sigd, SecIdentityRef identity, SECOidTag digestalgtag)
{
    SecCmsSignerInfoRef signerInfo = NULL;
    SecCertificateRef cert = NULL;
    SecPrivateKeyRef signingKey = NULL;
    CFDictionaryRef keyAttrs = NULL;

    if (SecIdentityCopyCertificate(identity, &cert)) {
        goto loser;
    }
    if (SecIdentityCopyPrivateKey(identity, &signingKey)) {
        goto loser;
    }

    /* In some situations, the "Private Key" in the identity is actually a public key. Check. */
    keyAttrs = SecKeyCopyAttributes(signingKey);
    if (!keyAttrs) {
        goto loser;
    }
    CFTypeRef class = CFDictionaryGetValue(keyAttrs, kSecAttrKeyClass);
    if (!class || (CFGetTypeID(class) != CFStringGetTypeID()) ||
        !CFEqual(class, kSecAttrKeyClassPrivate)) {
        goto loser;
    }

    signerInfo = nss_cmssignerinfo_create(sigd, SecCmsSignerIDIssuerSN, cert, NULL, NULL, signingKey, digestalgtag);

loser:
    CFReleaseNull(cert);
    CFReleaseNull(signingKey);
    CFReleaseNull(keyAttrs);

    return signerInfo;
}

SecCmsSignerInfoRef nss_cmssignerinfo_create(SecCmsSignedDataRef sigd,
                                             SecCmsSignerIDSelector type,
                                             SecCertificateRef cert,
                                             const SecAsn1Item* subjKeyID,
                                             SecPublicKeyRef pubKey,
                                             SecPrivateKeyRef signingKey,
                                             SECOidTag digestalgtag)
{
    void* mark;
    SecCmsSignerInfoRef signerinfo;
    int version;
    PLArenaPool* poolp;

    poolp = sigd->contentInfo.cmsg->poolp;

    mark = PORT_ArenaMark(poolp);

    signerinfo = (SecCmsSignerInfoRef)PORT_ArenaZAlloc(poolp, sizeof(SecCmsSignerInfo));
    if (signerinfo == NULL) {
        PORT_ArenaRelease(poolp, mark);
        return NULL;
    }


    signerinfo->signedData = sigd;

    switch (type) {
        case SecCmsSignerIDIssuerSN:
            signerinfo->signerIdentifier.identifierType = SecCmsSignerIDIssuerSN;
            if ((signerinfo->cert = CERT_DupCertificate(cert)) == NULL)
                goto loser;
            if ((signerinfo->signerIdentifier.id.issuerAndSN =
                     CERT_GetCertIssuerAndSN(poolp, cert)) == NULL)
                goto loser;
            break;
        case SecCmsSignerIDSubjectKeyID:
            signerinfo->signerIdentifier.identifierType = SecCmsSignerIDSubjectKeyID;
            PORT_Assert(subjKeyID);
            if (!subjKeyID) {
                goto loser;
            }
            signerinfo->signerIdentifier.id.subjectKeyID = PORT_ArenaNew(poolp, SecAsn1Item);
            if (SECITEM_CopyItem(poolp, signerinfo->signerIdentifier.id.subjectKeyID, subjKeyID)) {
                goto loser;
            }
            signerinfo->pubKey = SECKEY_CopyPublicKey(pubKey);
            if (!signerinfo->pubKey)
                goto loser;
            break;
        default:
            goto loser;
    }

    if (!signingKey)
        goto loser;

    signerinfo->signingKey = SECKEY_CopyPrivateKey(signingKey);
    if (!signerinfo->signingKey)
        goto loser;

    /* set version right now */
    version = SEC_CMS_SIGNER_INFO_VERSION_ISSUERSN;
    /* RFC2630 5.3 "version is the syntax version number. If the .... " */
    if (signerinfo->signerIdentifier.identifierType == SecCmsSignerIDSubjectKeyID)
        version = SEC_CMS_SIGNER_INFO_VERSION_SUBJKEY;
    (void)SEC_ASN1EncodeInteger(poolp, &(signerinfo->version), (long)version);

    if (SECOID_SetAlgorithmID(poolp, &signerinfo->digestAlg, digestalgtag, NULL) != SECSuccess)
        goto loser;

    if (SecCmsSignedDataAddSignerInfo(sigd, signerinfo))
        goto loser;

    PORT_ArenaUnmark(poolp, mark);
    return signerinfo;

loser:
    PORT_ArenaRelease(poolp, mark);
    return NULL;
}

/*
 * SecCmsSignerInfoDestroy - destroy a SignerInfo data structure
 */
void SecCmsSignerInfoDestroy(SecCmsSignerInfoRef si)
{
    if (si->cert != NULL) {
        CERT_DestroyCertificate(si->cert);
    }

    CFReleaseNull(si->certList);
    CFReleaseNull(si->hashAgilityAttrValue);
    CFReleaseNull(si->hashAgilityV2AttrValues);

    /* XXX storage ??? */
}

static SecAsn1AlgId SecCertificateGetPublicKeyAlgorithmID(SecCertificateRef cert)
{
    const DERAlgorithmId* length_data_swapped = SecCertificateGetPublicKeyAlgorithm(cert);
    SecAsn1AlgId temp = {{length_data_swapped->oid.length, length_data_swapped->oid.data},
                         {length_data_swapped->params.length, length_data_swapped->params.data}};

    return temp;
}

/*
 * SecCmsSignerInfoSign - sign something
 *
 */
OSStatus SecCmsSignerInfoSign(SecCmsSignerInfoRef signerinfo, SecAsn1Item* digest, SecAsn1Item* contentType)
{
    SecCertificateRef cert;
    SecPrivateKeyRef privkey = NULL;
    SECOidTag digestalgtag;
    SECOidTag pubkAlgTag;
    SecAsn1Item signature = {0};
    OSStatus rv;
    PLArenaPool *poolp, *tmppoolp = NULL;
    const SECAlgorithmID* algID = NULL;
    //CERTSubjectPublicKeyInfo *spki;

    PORT_Assert(digest != NULL);

    poolp = signerinfo->signedData->contentInfo.cmsg->poolp;

    SecAsn1AlgId _algID;

    switch (signerinfo->signerIdentifier.identifierType) {
        case SecCmsSignerIDIssuerSN:
            privkey = signerinfo->signingKey;
            signerinfo->signingKey = NULL;
            cert = signerinfo->cert;
            _algID = SecCertificateGetPublicKeyAlgorithmID(cert);
            algID = &_algID;
            break;
        case SecCmsSignerIDSubjectKeyID:
            privkey = signerinfo->signingKey;
            signerinfo->signingKey = NULL;
            CFReleaseNull(signerinfo->pubKey);
            break;
        default:
            PORT_SetError(SEC_ERROR_UNSUPPORTED_MESSAGE_TYPE);
            goto loser;
    }
    digestalgtag = SecCmsSignerInfoGetDigestAlgTag(signerinfo);
    pubkAlgTag = SECOID_GetAlgorithmTag(algID);

    /* we no longer support signing with MD5 */
    if (digestalgtag == SEC_OID_MD5) {
        PORT_SetError(SEC_ERROR_INVALID_ALGORITHM);
        goto loser;
    }

    if (signerinfo->authAttr != NULL) {
        SecAsn1Item encoded_attrs;

        /* find and fill in the message digest attribute. */
        rv = SecCmsAttributeArraySetAttr(poolp, &(signerinfo->authAttr), SEC_OID_PKCS9_MESSAGE_DIGEST, digest, PR_FALSE);
        if (rv != SECSuccess) {
            goto loser;
        }

        if (contentType != NULL) {
            /* if the caller wants us to, find and fill in the content type attribute. */
            rv = SecCmsAttributeArraySetAttr(poolp, &(signerinfo->authAttr), SEC_OID_PKCS9_CONTENT_TYPE, contentType, PR_FALSE);
            if (rv != SECSuccess) {
                goto loser;
            }
        }

        if ((tmppoolp = PORT_NewArena(1024)) == NULL) {
            PORT_SetError(SEC_ERROR_NO_MEMORY);
            goto loser;
        }

        /*
	 * Before encoding, reorder the attributes so that when they
	 * are encoded, they will be conforming DER, which is required
	 * to have a specific order and that is what must be used for
	 * the hash/signature.  We do this here, rather than building
	 * it into EncodeAttributes, because we do not want to do
	 * such reordering on incoming messages (which also uses
	 * EncodeAttributes) or our old signatures (and other "broken"
	 * implementations) will not verify.  So, we want to guarantee
	 * that we send out good DER encodings of attributes, but not
	 * to expect to receive them.
	 */
        if (SecCmsAttributeArrayReorder(signerinfo->authAttr) != SECSuccess) {
            goto loser;
        }

        encoded_attrs.Data = NULL;
        encoded_attrs.Length = 0;
        if (SecCmsAttributeArrayEncode(tmppoolp, &(signerinfo->authAttr), &encoded_attrs) == NULL) {
            goto loser;
        }

        signature.Length = SecKeyGetSize(privkey, kSecKeySignatureSize);
        signature.Data = PORT_ZAlloc(signature.Length);
        if (!signature.Data) {
            signature.Length = 0;
            goto loser;
        }
        rv = SecKeyDigestAndSign(privkey,
                                 &signerinfo->digestAlg,
                                 encoded_attrs.Data,
                                 encoded_attrs.Length,
                                 signature.Data,
                                 &signature.Length);
        if (rv) {
            PORT_ZFree(signature.Data, signature.Length);
            signature.Length = 0;
        }

        PORT_FreeArena(tmppoolp, PR_FALSE); /* awkward memory management :-( */
        tmppoolp = 0;
    } else {
        signature.Length = SecKeyGetSize(privkey, kSecKeySignatureSize);
        signature.Data = PORT_ZAlloc(signature.Length);
        if (!signature.Data) {
            signature.Length = 0;
            goto loser;
        }
        rv = SecKeySignDigest(privkey,
                              &signerinfo->digestAlg,
                              digest->Data,
                              digest->Length,
                              signature.Data,
                              &signature.Length);
        if (rv) {
            PORT_ZFree(signature.Data, signature.Length);
            signature.Length = 0;
        }
    }
    SECKEY_DestroyPrivateKey(privkey);
    privkey = NULL;

    if (rv != SECSuccess) {
        goto loser;
    }

    if (SECITEM_CopyItem(poolp, &(signerinfo->encDigest), &signature) != SECSuccess) {
        goto loser;
    }

    SECITEM_FreeItem(&signature, PR_FALSE);

    SECOidTag sigAlgTag = SecCmsUtilMakeSignatureAlgorithm(digestalgtag, pubkAlgTag);
    if (SECOID_SetAlgorithmID(poolp, &(signerinfo->digestEncAlg), sigAlgTag, NULL) != SECSuccess) {
        goto loser;
    }

    return SECSuccess;

loser:
    if (signature.Length != 0) {
        SECITEM_FreeItem(&signature, PR_FALSE);
    }
    if (privkey) {
        SECKEY_DestroyPrivateKey(privkey);
    }
    if (tmppoolp) {
        PORT_FreeArena(tmppoolp, PR_FALSE);
    }
    return SECFailure;
}

static CFArrayRef SecCmsSignerInfoCopySigningCertificates(SecCmsSignerInfoRef signerinfo)
{
    CFMutableArrayRef certs = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    SecAsn1Item** cert_datas = signerinfo->signedData->rawCerts;
    SecAsn1Item* cert_data;
    if (cert_datas) {
        while ((cert_data = *cert_datas) != NULL) {
            if (cert_data->Length > LONG_MAX) {
                continue;
            }
            SecCertificateRef cert =
                SecCertificateCreateWithBytes(NULL, cert_data->Data, (CFIndex)cert_data->Length);
            if (cert) {
                switch (signerinfo->signerIdentifier.identifierType) {
                    case SecCmsSignerIDIssuerSN:
                        if (CERT_CheckIssuerAndSerial(
                                cert,
                                &(signerinfo->signerIdentifier.id.issuerAndSN->derIssuer),
                                &(signerinfo->signerIdentifier.id.issuerAndSN->serialNumber)))
                            CFArrayInsertValueAtIndex(certs, 0, cert);
                        else
                            CFArrayAppendValue(certs, cert);
                        break;
                    case SecCmsSignerIDSubjectKeyID: {
                        CFDataRef cert_keyid = SecCertificateGetSubjectKeyID(cert);
                        SecAsn1Item* tbf_keyid = signerinfo->signerIdentifier.id.subjectKeyID;
                        if (tbf_keyid->Length == (size_t)CFDataGetLength(cert_keyid) &&
                            !memcmp(
                                tbf_keyid->Data, CFDataGetBytePtr(cert_keyid), tbf_keyid->Length))
                            CFArrayInsertValueAtIndex(certs, 0, cert);
                        else
                            CFArrayAppendValue(certs, cert);
                        break;
                    }
                }
                CFReleaseNull(cert);
            }
            cert_datas++;
        }
    }

    if ((CFArrayGetCount(certs) == 0) &&
        (signerinfo->signerIdentifier.identifierType == SecCmsSignerIDIssuerSN)) {
        SecCertificateRef cert = CERT_FindCertificateByIssuerAndSN(
            signerinfo->signedData->certs, signerinfo->signerIdentifier.id.issuerAndSN);
        if (cert) {
            CFArrayAppendValue(certs, cert);
            CFReleaseNull(cert);
        }
    }

    if ((CFArrayGetCount(certs) == 0) &&
        (signerinfo->signerIdentifier.identifierType == SecCmsSignerIDSubjectKeyID)) {
        SecCertificateRef cert = CERT_FindCertificateBySubjectKeyID(
            signerinfo->signedData->certs, signerinfo->signerIdentifier.id.subjectKeyID);
        if (cert) {
            CFArrayAppendValue(certs, cert);
            CFReleaseNull(cert);
        }
    }
    return certs;
}

OSStatus SecCmsSignerInfoVerifyCertificate(SecCmsSignerInfoRef signerinfo,
                                           SecKeychainRef keychainOrArray,
                                           CFTypeRef policies,
                                           SecTrustRef* trustRef)
{
    CFAbsoluteTime stime;
    OSStatus rv;

    CFArrayRef certs;

    if ((certs = SecCmsSignerInfoCopySigningCertificates(signerinfo)) == NULL) {
        signerinfo->verificationStatus = SecCmsVSSigningCertNotFound;
        return SECFailure;
    }
    /*
     * Get and convert the signing time; if available, it will be used
     * both on the cert verification and for importing the sender
     * email profile.
     */
    if (SecCmsSignerInfoGetSigningTime(signerinfo, &stime) != SECSuccess) {
        stime = CFAbsoluteTimeGetCurrent();
    }

    rv = CERT_VerifyCert(keychainOrArray, certs, policies, stime, trustRef);
    CFReleaseNull(certs);
    if (rv || !trustRef) {
        if (PORT_GetError() == SEC_ERROR_UNTRUSTED_CERT) {
            /* Signature or digest level verificationStatus errors should supercede certificate level errors, so only change the verificationStatus if the status was GoodSignature. */
            if (signerinfo->verificationStatus == SecCmsVSGoodSignature) {
                signerinfo->verificationStatus = SecCmsVSSigningCertNotTrusted;
            }
        }
    }

    return rv;
}

/*
 * SecCmsSignerInfoVerify - verify the signature of a single SignerInfo
 *
 * Just verifies the signature. The assumption is that verification of the certificate
 * is done already.
 */
OSStatus SecCmsSignerInfoVerify(SecCmsSignerInfoRef signerinfo, SecAsn1Item* digest, SecAsn1Item* contentType)
{
    SecPublicKeyRef publickey = NULL;
    SecCmsAttribute* attr;
    SecAsn1Item encoded_attrs;
    SecCertificateRef cert;
    SecCmsVerificationStatus vs = SecCmsVSUnverified;
    PLArenaPool* poolp;

    if (signerinfo == NULL) {
        return SECFailure;
    }

    /* SecCmsSignerInfoGetSigningCertificate will fail if 2nd parm is NULL and */
    /* cert has not been verified */
    if ((cert = SecCmsSignerInfoGetSigningCert(signerinfo)) == NULL) {
        vs = SecCmsVSSigningCertNotFound;
        goto loser;
    }

    publickey = SecCertificateCopyKey(cert);
    if (publickey == NULL) {
        goto loser;
    }

    if (!SecCmsArrayIsEmpty((void**)signerinfo->authAttr)) {
        if (contentType) {
            /*
             * Check content type
             *
             * RFC2630 sez that if there are any authenticated attributes,
             * then there must be one for content type which matches the
             * content type of the content being signed, and there must
             * be one for message digest which matches our message digest.
             * So check these things first.
             */
            if ((attr = SecCmsAttributeArrayFindAttrByOidTag(
                     signerinfo->authAttr, SEC_OID_PKCS9_CONTENT_TYPE, PR_TRUE)) == NULL) {
                vs = SecCmsVSMalformedSignature;
                goto loser;
            }

            if (SecCmsAttributeCompareValue(attr, contentType) == PR_FALSE) {
                vs = SecCmsVSMalformedSignature;
                goto loser;
            }
        }

        /*
         * Check digest
         */
        if ((attr = SecCmsAttributeArrayFindAttrByOidTag(
                 signerinfo->authAttr, SEC_OID_PKCS9_MESSAGE_DIGEST, PR_TRUE)) == NULL) {
            vs = SecCmsVSMalformedSignature;
            goto loser;
        }
        if (SecCmsAttributeCompareValue(attr, digest) == PR_FALSE) {
            vs = SecCmsVSDigestMismatch;
            goto loser;
        }

        if ((poolp = PORT_NewArena(1024)) == NULL) {
            vs = SecCmsVSProcessingError;
            goto loser;
        }

        /*
         * Check signature
         *
         * The signature is based on a digest of the DER-encoded authenticated
         * attributes.  So, first we encode and then we digest/verify.
         * we trust the decoder to have the attributes in the right (sorted) order
         */
        encoded_attrs.Data = NULL;
        encoded_attrs.Length = 0;

        if (SecCmsAttributeArrayEncode(poolp, &(signerinfo->authAttr), &encoded_attrs) == NULL ||
            encoded_attrs.Data == NULL || encoded_attrs.Length == 0) {
            vs = SecCmsVSProcessingError;
            goto loser;
        }
        if (errSecSuccess == SecKeyDigestAndVerify(publickey,
                                                   &signerinfo->digestAlg,
                                                   encoded_attrs.Data,
                                                   encoded_attrs.Length,
                                                   signerinfo->encDigest.Data,
                                                   signerinfo->encDigest.Length)) {
            vs = SecCmsVSGoodSignature;
        } else {
            vs = SecCmsVSBadSignature;
        }

        PORT_FreeArena(poolp, PR_FALSE); /* awkward memory management :-( */

    } else {
        SecAsn1Item* sig;

        /* No authenticated attributes. The signature is based on the plain message digest. */
        sig = &(signerinfo->encDigest);
        if (sig->Length == 0) {
            goto loser;
        }

        if (SecKeyVerifyDigest(publickey, &signerinfo->digestAlg, digest->Data, digest->Length, sig->Data, sig->Length)) {
            vs = SecCmsVSBadSignature;
        } else {
            vs = SecCmsVSGoodSignature;
        }
    }

    if (vs == SecCmsVSBadSignature) {
        /*
         * XXX Change the generic error into our specific one, because
         * in that case we get a better explanation out of the Security
         * Advisor.  This is really a bug in our error strings (the
         * "generic" error has a lousy/wrong message associated with it
         * which assumes the signature verification was done for the
         * purposes of checking the issuer signature on a certificate)
         * but this is at least an easy workaround and/or in the
         * Security Advisor, which specifically checks for the error
         * SEC_ERROR_PKCS7_BAD_SIGNATURE and gives more explanation
         * in that case but does not similarly check for
         * SEC_ERROR_BAD_SIGNATURE.  It probably should, but then would
         * probably say the wrong thing in the case that it *was* the
         * certificate signature check that failed during the cert
         * verification done above.  Our error handling is really a mess.
         */
        if (PORT_GetError() == SEC_ERROR_BAD_SIGNATURE)
            PORT_SetError(SEC_ERROR_PKCS7_BAD_SIGNATURE);
    }

    CFReleaseNull(publickey);

    signerinfo->verificationStatus = vs;

    return (vs == SecCmsVSGoodSignature) ? SECSuccess : SECFailure;

loser:
    if (publickey != NULL) {
        SECKEY_DestroyPublicKey(publickey);
    }

    signerinfo->verificationStatus = vs;

    PORT_SetError(SEC_ERROR_PKCS7_BAD_SIGNATURE);
    return SECFailure;
}

SecCmsVerificationStatus SecCmsSignerInfoGetVerificationStatus(SecCmsSignerInfoRef signerinfo)
{
    return signerinfo->verificationStatus;
}

SECOidData* SecCmsSignerInfoGetDigestAlg(SecCmsSignerInfoRef signerinfo)
{
    return SECOID_FindOID(&(signerinfo->digestAlg.algorithm));
}

SECOidTag SecCmsSignerInfoGetDigestAlgTag(SecCmsSignerInfoRef signerinfo)
{
    SECOidData* algdata;

    algdata = SECOID_FindOID(&(signerinfo->digestAlg.algorithm));
    if (algdata != NULL)
        return algdata->offset;
    else
        return SEC_OID_UNKNOWN;
}

CFArrayRef SecCmsSignerInfoGetCertList(SecCmsSignerInfoRef signerinfo)
{
    return signerinfo->certList;
}

int SecCmsSignerInfoGetVersion(SecCmsSignerInfoRef signerinfo)
{
    unsigned long version;

    /* always take apart the SecAsn1Item */
    if (SEC_ASN1DecodeInteger(&(signerinfo->version), &version) != SECSuccess)
        return 0;
    else
        return (int)version;
}

/*
 * SecCmsSignerInfoGetSigningTime - return the signing time,
 *				      in UTCTime format, of a CMS signerInfo.
 *
 * sinfo - signerInfo data for this signer
 *
 * Returns a pointer to XXXX (what?)
 * A return value of NULL is an error.
 */
OSStatus SecCmsSignerInfoGetSigningTime(SecCmsSignerInfoRef sinfo, CFAbsoluteTime* stime)
{
    SecCmsAttribute* attr;
    SecAsn1Item* value;

    if (sinfo == NULL)
        return SECFailure;

    if (sinfo->signingTime != 0) {
        *stime = sinfo->signingTime; /* cached copy */
        return SECSuccess;
    }

    attr = SecCmsAttributeArrayFindAttrByOidTag(sinfo->authAttr, SEC_OID_PKCS9_SIGNING_TIME, PR_TRUE);
    if (attr == NULL || (value = SecCmsAttributeGetValue(attr)) == NULL)
        return SECFailure;
    if (SecAsn1DecodeTime(value, stime) != SECSuccess)
        return SECFailure;
    sinfo->signingTime = *stime; /* make cached copy */
    return SECSuccess;
}

/*!
     @function
     @abstract Return the data in the signed Codesigning Hash Agility attribute.
     @param sinfo SignerInfo data for this signer, pointer to a CFDataRef for attribute value
     @discussion Returns a CFDataRef containing the value of the attribute
     @result A return value of errSecInternal is an error trying to look up the oid.
             A status value of success with null result data indicates the attribute was not present.
 */
OSStatus SecCmsSignerInfoGetAppleCodesigningHashAgility(SecCmsSignerInfoRef sinfo, CFDataRef* sdata)
{
    SecCmsAttribute* attr;
    SecAsn1Item* value;

    if (sinfo == NULL || sdata == NULL) {
        return errSecParam;
    }

    *sdata = NULL;

    if (sinfo->hashAgilityAttrValue != NULL) {
        *sdata = sinfo->hashAgilityAttrValue; /* cached copy */
        return SECSuccess;
    }

    attr = SecCmsAttributeArrayFindAttrByOidTag(sinfo->authAttr, SEC_OID_APPLE_HASH_AGILITY, PR_TRUE);

    /* attribute not found */
    if (attr == NULL || (value = SecCmsAttributeGetValue(attr)) == NULL) {
        return SECSuccess;
    }

    if (value->Length > LONG_MAX) {
        return errSecAllocate;
    }
    sinfo->hashAgilityAttrValue = CFDataCreate(NULL, value->Data, (CFIndex)value->Length); /* make cached copy */
    if (sinfo->hashAgilityAttrValue) {
        *sdata = sinfo->hashAgilityAttrValue;
        return SECSuccess;
    }
    return errSecAllocate;
}

/* AgileHash ::= SEQUENCE {
     hashType OBJECT IDENTIFIER,
     hashValues OCTET STRING }
*/
typedef struct {
    SecAsn1Item digestOID;
    SecAsn1Item digestValue;
} CMSAppleAgileHash;

static const SecAsn1Template CMSAppleAgileHashTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(CMSAppleAgileHash)},
    {
        SEC_ASN1_OBJECT_ID,
        offsetof(CMSAppleAgileHash, digestOID),
    },
    {
        SEC_ASN1_OCTET_STRING,
        offsetof(CMSAppleAgileHash, digestValue),
    },
    {
        0,
    }};

static OSStatus CMSAddAgileHashToDictionary(CFMutableDictionaryRef dictionary, SecAsn1Item* DERAgileHash)
{
    PLArenaPool* tmppoolp = NULL;
    OSStatus status = errSecSuccess;
    CMSAppleAgileHash agileHash;
    CFDataRef digestValue = NULL;
    CFNumberRef digestTag = NULL;

    tmppoolp = PORT_NewArena(1024);
    if (tmppoolp == NULL) {
        return errSecAllocate;
    }

    if ((status = SEC_ASN1DecodeItem(tmppoolp, &agileHash, CMSAppleAgileHashTemplate, DERAgileHash)) !=
        errSecSuccess) {
        goto loser;
    }
    if (agileHash.digestValue.Length > LONG_MAX) {
        status = errSecAllocate;
        goto loser;
    }

    int64_t tag = SECOID_FindOIDTag(&agileHash.digestOID);
    digestTag = CFNumberCreate(NULL, kCFNumberSInt64Type, &tag);
    digestValue = CFDataCreate(NULL, agileHash.digestValue.Data, (CFIndex)agileHash.digestValue.Length);
    CFDictionaryAddValue(dictionary, digestTag, digestValue);

loser:
    CFReleaseNull(digestValue);
    CFReleaseNull(digestTag);
    if (tmppoolp) {
        PORT_FreeArena(tmppoolp, PR_FALSE);
    }
    return status;
}

/*!
 @function
 @abstract Return the data in the signed Codesigning Hash Agility V2 attribute.
 @param sinfo SignerInfo data for this signer, pointer to a CFDictionaryRef for attribute values
 @discussion Returns a CFDictionaryRef containing the values of the attribute
 @result A return value of errSecInternal is an error trying to look up the oid.
 A status value of success with null result data indicates the attribute was not present.
 */
OSStatus SecCmsSignerInfoGetAppleCodesigningHashAgilityV2(SecCmsSignerInfoRef sinfo, CFDictionaryRef* sdict)
{
    SecCmsAttribute* attr;

    if (sinfo == NULL || sdict == NULL) {
        return errSecParam;
    }

    *sdict = NULL;

    if (sinfo->hashAgilityV2AttrValues != NULL) {
        *sdict = sinfo->hashAgilityV2AttrValues; /* cached copy */
        return SECSuccess;
    }

    attr = SecCmsAttributeArrayFindAttrByOidTag(sinfo->authAttr, SEC_OID_APPLE_HASH_AGILITY_V2, PR_TRUE);

    /* attribute not found */
    if (attr == NULL) {
        return SECSuccess;
    }

    /* attrValues SET OF AttributeValue
     * AttributeValue ::= ANY
     */
    SecAsn1Item** values = attr->values;
    if (values == NULL) { /* There must be values */
        return errSecDecode;
    }

    CFMutableDictionaryRef agileHashValues = CFDictionaryCreateMutable(
        NULL, SecCmsArrayCount((void**)values), &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    while (*values != NULL) {
        (void)CMSAddAgileHashToDictionary(agileHashValues, *values++);
    }
    if (CFDictionaryGetCount(agileHashValues) != SecCmsArrayCount((void**)attr->values)) {
        CFReleaseNull(agileHashValues);
        return errSecDecode;
    }

    sinfo->hashAgilityV2AttrValues = agileHashValues; /* make cached copy */
    if (sinfo->hashAgilityV2AttrValues) {
        *sdict = sinfo->hashAgilityV2AttrValues;
        return SECSuccess;
    }
    return errSecAllocate;
}

/*
 * SecCmsSignerInfoGetAppleExpirationTime - return the expiration time,
 *                      in UTCTime format, of a CMS signerInfo.
 *
 * sinfo - signerInfo data for this signer
 *
 * Returns a pointer to XXXX (what?)
 * A return value of NULL is an error.
 */
OSStatus SecCmsSignerInfoGetAppleExpirationTime(SecCmsSignerInfoRef sinfo, CFAbsoluteTime* etime)
{
    SecCmsAttribute* attr = NULL;
    SecAsn1Item* value = NULL;

    if (sinfo == NULL || etime == NULL) {
        return SECFailure;
    }

    if (sinfo->expirationTime != 0) {
        *etime = sinfo->expirationTime; /* cached copy */
        return SECSuccess;
    }

    attr = SecCmsAttributeArrayFindAttrByOidTag(sinfo->authAttr, SEC_OID_APPLE_EXPIRATION_TIME, PR_TRUE);
    if (attr == NULL || (value = SecCmsAttributeGetValue(attr)) == NULL) {
        return SECFailure;
    }
    if (SecAsn1DecodeTime(value, etime) != SECSuccess) {
        return SECFailure;
    }
    sinfo->expirationTime = *etime; /* make cached copy */
    return SECSuccess;
}

/*
 * Return the signing cert of a CMS signerInfo.
 *
 * the certs in the enclosing SignedData must have been imported already
 */
static SecCertificateRef SecCmsSignerInfoGetSigningCert_internal(SecCmsSignerInfoRef signerinfo, SecKeychainRef keychainOrArray)
{
    SecCertificateRef cert = NULL;

    if (signerinfo->cert != NULL)
        return signerinfo->cert;

        /* @@@ Make sure we search though all the certs in the cms message itself as well, it's silly
       to require them to be added to a keychain first. */

    SecAsn1Item** cert_datas = signerinfo->signedData->rawCerts;
    SecAsn1Item* cert_data;
    if (cert_datas) {
        while ((cert_data = *cert_datas) != NULL) {
            if (cert_data->Length > LONG_MAX) {
                continue;
            }
            cert = SecCertificateCreateWithBytes(NULL, cert_data->Data, (CFIndex)cert_data->Length);
            if (cert) {
                switch (signerinfo->signerIdentifier.identifierType) {
                    case SecCmsSignerIDIssuerSN:
                        if (CERT_CheckIssuerAndSerial(
                                cert,
                                &(signerinfo->signerIdentifier.id.issuerAndSN->derIssuer),
                                &(signerinfo->signerIdentifier.id.issuerAndSN->serialNumber)))
                            signerinfo->cert = cert;
                        break;
                    case SecCmsSignerIDSubjectKeyID: {
                        CFDataRef cert_keyid = SecCertificateGetSubjectKeyID(cert);
                        SecAsn1Item* tbf_keyid = signerinfo->signerIdentifier.id.subjectKeyID;
                        if (tbf_keyid->Length == (size_t)CFDataGetLength(cert_keyid) &&
                            !memcmp(
                                tbf_keyid->Data, CFDataGetBytePtr(cert_keyid), tbf_keyid->Length))
                            signerinfo->cert = cert;
                    }
                }
                if (signerinfo->cert)
                    break;
                CFReleaseNull(cert);
            }
            cert_datas++;
        }
    }

    if (!signerinfo->cert && (signerinfo->signerIdentifier.identifierType == SecCmsSignerIDIssuerSN)) {
        cert = CERT_FindCertificateByIssuerAndSN(signerinfo->signedData->certs,
                                                 signerinfo->signerIdentifier.id.issuerAndSN);
        signerinfo->cert = cert;
    }
    if (!signerinfo->cert && (signerinfo->signerIdentifier.identifierType == SecCmsSignerIDSubjectKeyID)) {
        cert = CERT_FindCertificateBySubjectKeyID(
            signerinfo->signedData->certs, signerinfo->signerIdentifier.id.subjectKeyID);
        signerinfo->cert = cert;
    }

    return cert;
}

SecCertificateRef SecCmsSignerInfoGetSigningCert(SecCmsSignerInfoRef signerinfo)
{
    return SecCmsSignerInfoGetSigningCert_internal(signerinfo, NULL);
}

SecCertificateRef SecCmsSignerInfoGetSigningCertificate(SecCmsSignerInfoRef signerinfo, SecKeychainRef keychainOrArray)
{
    return SecCmsSignerInfoGetSigningCert_internal(signerinfo, keychainOrArray);
}

/*
 * SecCmsSignerInfoGetSignerCommonName - return the common name of the signer
 *
 * sinfo - signerInfo data for this signer
 *
 * Returns a CFStringRef containing the common name of the signer.
 * A return value of NULL is an error.
 */
CFStringRef SecCmsSignerInfoGetSignerCommonName(SecCmsSignerInfoRef sinfo)
{
    SecCertificateRef signercert;
    CFStringRef commonName = NULL;

    /* will fail if cert is not verified */
    if ((signercert = SecCmsSignerInfoGetSigningCert(sinfo)) == NULL) {
        return NULL;
    }

    CFArrayRef commonNames = SecCertificateCopyCommonNames(signercert);
    if (commonNames) {
        /* SecCertificateCopyCommonNames doesn't return empty arrays */
        commonName =
            (CFStringRef)CFArrayGetValueAtIndex(commonNames, CFArrayGetCount(commonNames) - 1);
        CFRetainSafe(commonName);
        CFReleaseNull(commonNames);
    }

    return commonName;
}

/*
 * SecCmsSignerInfoGetSignerEmailAddress - return the email address of the signer
 *
 * sinfo - signerInfo data for this signer
 *
 * Returns a CFStringRef containing the name of the signer.
 * A return value of NULL is an error.
 */
CFStringRef SecCmsSignerInfoGetSignerEmailAddress(SecCmsSignerInfoRef sinfo)
{
    SecCertificateRef signercert;
    CFStringRef emailAddress = NULL;

    if ((signercert = SecCmsSignerInfoGetSigningCert(sinfo)) == NULL) {
        return NULL;
    }

    CFArrayRef names = SecCertificateCopyRFC822Names(signercert);
    if (names) {
        if (CFArrayGetCount(names) > 0) {
            emailAddress = (CFStringRef)CFArrayGetValueAtIndex(names, 0);
        }
        CFRetainSafe(emailAddress);
        CFReleaseNull(names);
    }
    return emailAddress;
}


/*
 * SecCmsSignerInfoAddAuthAttr - add an attribute to the
 * authenticated (i.e. signed) attributes of "signerinfo". 
 */
OSStatus SecCmsSignerInfoAddAuthAttr(SecCmsSignerInfoRef signerinfo, SecCmsAttribute* attr)
{
    return SecCmsAttributeArrayAddAttr(
        signerinfo->signedData->contentInfo.cmsg->poolp, &(signerinfo->authAttr), attr);
}

/*
 * SecCmsSignerInfoAddUnauthAttr - add an attribute to the
 * unauthenticated attributes of "signerinfo". 
 */
OSStatus SecCmsSignerInfoAddUnauthAttr(SecCmsSignerInfoRef signerinfo, SecCmsAttribute* attr)
{
    return SecCmsAttributeArrayAddAttr(
        signerinfo->signedData->contentInfo.cmsg->poolp, &(signerinfo->unAuthAttr), attr);
}

/* 
 * SecCmsSignerInfoAddSigningTime - add the signing time to the
 * authenticated (i.e. signed) attributes of "signerinfo". 
 *
 * This is expected to be included in outgoing signed
 * messages for email (S/MIME) but is likely useful in other situations.
 *
 * This should only be added once; a second call will do nothing.
 *
 * XXX This will probably just shove the current time into "signerinfo"
 * but it will not actually get signed until the entire item is
 * processed for encoding.  Is this (expected to be small) delay okay?
 */
OSStatus SecCmsSignerInfoAddSigningTime(SecCmsSignerInfoRef signerinfo, CFAbsoluteTime t)
{
    SecCmsAttribute* attr;
    SecAsn1Item stime = { .Data = NULL, .Length = 0 };
    void* mark;
    PLArenaPool* poolp;
    OSStatus status = errSecInternal;

    poolp = signerinfo->signedData->contentInfo.cmsg->poolp;

    mark = PORT_ArenaMark(poolp);

    /* create new signing time attribute */
    NSS_Time timeStr;
    if (SecAsn1EncodeTime(poolp, t, &timeStr) != SECSuccess) {
        goto loser;
    }

    if (SEC_ASN1EncodeItem(poolp, &stime, &timeStr, kSecAsn1TimeTemplate) != &stime) {
        goto loser;
    }

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_PKCS9_SIGNING_TIME, &stime, PR_TRUE)) == NULL) {
        goto loser;
    }

    if ((status = SecCmsSignerInfoAddAuthAttr(signerinfo, attr)) != SECSuccess) {
        goto loser;
    }

    PORT_ArenaUnmark(poolp, mark);

    return status;

loser:
    PORT_ArenaRelease(poolp, mark);
    return status;
}

/* 
 * SecCmsSignerInfoAddSMIMECaps - add a SMIMECapabilities attribute to the
 * authenticated (i.e. signed) attributes of "signerinfo". 
 *
 * This is expected to be included in outgoing signed
 * messages for email (S/MIME).
 */
OSStatus SecCmsSignerInfoAddSMIMECaps(SecCmsSignerInfoRef signerinfo)
{
    SecCmsAttribute* attr;
    SecAsn1Item* smimecaps = NULL;
    void* mark;
    PLArenaPool* poolp;

    poolp = signerinfo->signedData->contentInfo.cmsg->poolp;

    mark = PORT_ArenaMark(poolp);

    smimecaps = SECITEM_AllocItem(poolp, NULL, 0);
    if (smimecaps == NULL) {
        goto loser;
    }

    /* create new signing time attribute */
#if 1
    // @@@ We don't do Fortezza yet.
    if (SecSMIMECreateSMIMECapabilities(poolp, smimecaps, PR_FALSE) != SECSuccess)
#else
    if (SecSMIMECreateSMIMECapabilities(poolp, smimecaps, PK11_FortezzaHasKEA(signerinfo->cert)) != SECSuccess)
#endif
        goto loser;

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_PKCS9_SMIME_CAPABILITIES, smimecaps, PR_TRUE)) == NULL)
        goto loser;

    if (SecCmsSignerInfoAddAuthAttr(signerinfo, attr) != SECSuccess)
        goto loser;

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

loser:
    PORT_ArenaRelease(poolp, mark);
    return SECFailure;
}

/* 
 * SecCmsSignerInfoAddSMIMEEncKeyPrefs - add a SMIMEEncryptionKeyPreferences attribute to the
 * authenticated (i.e. signed) attributes of "signerinfo". 
 *
 * This is expected to be included in outgoing signed messages for email (S/MIME).
 */
static OSStatus SecCmsSignerInfoAddSMIMEEncKeyPrefs_internal(SecCmsSignerInfoRef signerinfo,
                                             SecCertificateRef cert,
                                             SecKeychainRef keychainOrArray)
{
    SecCmsAttribute* attr;
    SecAsn1Item* smimeekp = NULL;
    void* mark;
    PLArenaPool* poolp;

    poolp = signerinfo->signedData->contentInfo.cmsg->poolp;
    mark = PORT_ArenaMark(poolp);

    smimeekp = SECITEM_AllocItem(poolp, NULL, 0);
    if (smimeekp == NULL) {
        goto loser;
    }

    /* create new signing time attribute */
    if (SecSMIMECreateSMIMEEncKeyPrefs(poolp, smimeekp, cert) != SECSuccess)
        goto loser;

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE, smimeekp, PR_TRUE)) == NULL) {
        goto loser;
    }

    if (SecCmsSignerInfoAddAuthAttr(signerinfo, attr) != SECSuccess) {
        goto loser;
    }

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

loser:
    PORT_ArenaRelease(poolp, mark);
    return SECFailure;
}

OSStatus SecCmsSignerInfoAddSMIMEEncKeyPrefs(SecCmsSignerInfoRef signerinfo,
                                             SecCertificateRef cert,
                                             SecKeychainRef keychainOrArray)
{
    return SecCmsSignerInfoAddSMIMEEncKeyPrefs_internal(signerinfo, cert, keychainOrArray);
}

OSStatus SecCmsSignerInfoAddSMIMEEncKeyPreferences(SecCmsSignerInfoRef signerinfo, SecCertificateRef cert)
{
    return SecCmsSignerInfoAddSMIMEEncKeyPrefs_internal(signerinfo, cert, NULL);
}

/* 
 * SecCmsSignerInfoAddMSSMIMEEncKeyPrefs - add a SMIMEEncryptionKeyPreferences attribute to the
 * authenticated (i.e. signed) attributes of "signerinfo", using the OID preferred by Microsoft.
 *
 * This is expected to be included in outgoing signed messages for email (S/MIME),
 * if compatibility with Microsoft mail clients is wanted.
 */
static OSStatus SecCmsSignerInfoAddMSSMIMEEncKeyPrefs_internal(SecCmsSignerInfoRef signerinfo,
                                               SecCertificateRef cert,
                                               SecKeychainRef keychainOrArray)
{
    SecCmsAttribute* attr;
    SecAsn1Item* smimeekp = NULL;
    void* mark;
    PLArenaPool* poolp;

    poolp = signerinfo->signedData->contentInfo.cmsg->poolp;
    mark = PORT_ArenaMark(poolp);

    smimeekp = SECITEM_AllocItem(poolp, NULL, 0);
    if (smimeekp == NULL) {
        goto loser;
    }

    /* create new signing time attribute */
    if (SecSMIMECreateMSSMIMEEncKeyPrefs(poolp, smimeekp, cert) != SECSuccess) {
        goto loser;
    }

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE, smimeekp, PR_TRUE)) == NULL) {
        goto loser;
    }

    if (SecCmsSignerInfoAddAuthAttr(signerinfo, attr) != SECSuccess) {
        goto loser;
    }

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

loser:
    PORT_ArenaRelease(poolp, mark);
    return SECFailure;
}

OSStatus SecCmsSignerInfoAddMSSMIMEEncKeyPrefs(SecCmsSignerInfoRef signerinfo,
                                             SecCertificateRef cert,
                                             SecKeychainRef keychainOrArray)
{
    return SecCmsSignerInfoAddMSSMIMEEncKeyPrefs_internal(signerinfo, cert, keychainOrArray);
}

OSStatus SecCmsSignerInfoAddMSSMIMEEncKeyPreferences(SecCmsSignerInfoRef signerinfo, SecCertificateRef cert)
{
    return SecCmsSignerInfoAddMSSMIMEEncKeyPrefs_internal(signerinfo, cert, NULL);
}

/* 
 * SecCmsSignerInfoAddCounterSignature - countersign a signerinfo
 *
 * 1. digest the DER-encoded signature value of the original signerinfo
 * 2. create new signerinfo with correct version, sid, digestAlg
 * 3. add message-digest authAttr, but NO content-type
 * 4. sign the authAttrs
 * 5. DER-encode the new signerInfo
 * 6. add the whole thing to original signerInfo's unAuthAttrs
 *    as a SEC_OID_PKCS9_COUNTER_SIGNATURE attribute
 *
 * XXXX give back the new signerinfo?
 */
OSStatus SecCmsSignerInfoAddCounterSignature(SecCmsSignerInfoRef signerinfo,
                                             SECOidTag digestalg,
                                             SecIdentityRef identity)
{
    /* XXXX TBD XXXX */
    return SECFailure;
}

/*!
     @function
     @abstract Add the Apple Codesigning Hash Agility attribute to the authenticated (i.e. signed) attributes of "signerinfo".
     @discussion This is expected to be included in outgoing Apple code signatures.
 */
OSStatus SecCmsSignerInfoAddAppleCodesigningHashAgility(SecCmsSignerInfoRef signerinfo, CFDataRef attrValue)
{
    SecCmsAttribute* attr;
    PLArenaPool* poolp = signerinfo->signedData->contentInfo.cmsg->poolp;
    void* mark = PORT_ArenaMark(poolp);
    OSStatus status = SECFailure;

    /* The value is required for this attribute. */
    if (!attrValue || CFDataGetLength(attrValue) < 0) {
        status = errSecParam;
        goto loser;
    }

    /*
     * SecCmsAttributeCreate makes a copy of the data in value, so
     * we don't need to copy into the CSSM_DATA struct.
     */
    SecAsn1Item value;
    value.Length = (size_t)CFDataGetLength(attrValue);
    value.Data = (uint8_t*)CFDataGetBytePtr(attrValue);

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_APPLE_HASH_AGILITY, &value, PR_FALSE)) == NULL) {
        status = errSecAllocate;
        goto loser;
    }

    if (SecCmsSignerInfoAddAuthAttr(signerinfo, attr) != SECSuccess) {
        status = errSecInternal;
        goto loser;
    }

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

loser:
    PORT_ArenaRelease(poolp, mark);
    return status;
}

static OSStatus
CMSAddAgileHashToAttribute(PLArenaPool* poolp, SecCmsAttribute* attr, CFNumberRef cftag, CFDataRef value)
{
    PLArenaPool* tmppoolp = NULL;
    int64_t tag;
    SECOidData* digestOid = NULL;
    CMSAppleAgileHash agileHash;
    SecAsn1Item attrValue = {.Data = NULL, .Length = 0};
    OSStatus status = errSecSuccess;

    memset(&agileHash, 0, sizeof(agileHash));

    if (!CFNumberGetValue(cftag, kCFNumberSInt64Type, &tag) || CFDataGetLength(value) < 0) {
        return errSecParam;
    }
    digestOid = SECOID_FindOIDByTag((SECOidTag)tag);

    agileHash.digestValue.Data = (uint8_t*)CFDataGetBytePtr(value);
    agileHash.digestValue.Length = (size_t)CFDataGetLength(value);
    agileHash.digestOID.Data = digestOid->oid.Data;
    agileHash.digestOID.Length = digestOid->oid.Length;

    tmppoolp = PORT_NewArena(1024);
    if (tmppoolp == NULL) {
        return errSecAllocate;
    }

    if (SEC_ASN1EncodeItem(tmppoolp, &attrValue, &agileHash, CMSAppleAgileHashTemplate) == NULL) {
        status = errSecParam;
        goto loser;
    }

    status = SecCmsAttributeAddValue(poolp, attr, &attrValue);

loser:
    if (tmppoolp) {
        PORT_FreeArena(tmppoolp, PR_FALSE);
    }
    return status;
}

/*!
 @function
 @abstract Add the Apple Codesigning Hash Agility attribute to the authenticated (i.e. signed) attributes of "signerinfo".
 @discussion This is expected to be included in outgoing Apple code signatures.
 */
OSStatus SecCmsSignerInfoAddAppleCodesigningHashAgilityV2(SecCmsSignerInfoRef signerinfo,
                                                          CFDictionaryRef attrValues)
{
    __block SecCmsAttribute* attr;
    __block PLArenaPool* poolp = signerinfo->signedData->contentInfo.cmsg->poolp;
    void* mark = PORT_ArenaMark(poolp);
    OSStatus status = SECFailure;

    /* The value is required for this attribute. */
    if (!attrValues) {
        status = errSecParam;
        goto loser;
    }

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_APPLE_HASH_AGILITY_V2, NULL, PR_TRUE)) == NULL) {
        status = errSecAllocate;
        goto loser;
    }

    CFDictionaryForEach(attrValues, ^(const void* key, const void* value) {
        if (!isNumber(key) || !isData(value)) {
            return;
        }
        (void)CMSAddAgileHashToAttribute(poolp, attr, (CFNumberRef)key, (CFDataRef)value);
    });

    if (SecCmsSignerInfoAddAuthAttr(signerinfo, attr) != SECSuccess) {
        status = errSecInternal;
        goto loser;
    }

    PORT_ArenaUnmark(poolp, mark);
    return SECSuccess;

loser:
    PORT_ArenaRelease(poolp, mark);
    return status;
}

/*
 * SecCmsSignerInfoAddAppleExpirationTime - add the expiration time to the
 * authenticated (i.e. signed) attributes of "signerinfo".
 *
 * This is expected to be included in outgoing signed
 * messages for Asset Receipts but is likely useful in other situations.
 *
 * This should only be added once; a second call will do nothing.
 */
OSStatus SecCmsSignerInfoAddAppleExpirationTime(SecCmsSignerInfoRef signerinfo, CFAbsoluteTime t)
{
    SecCmsAttribute* attr = NULL;
    PLArenaPool* poolp = signerinfo->signedData->contentInfo.cmsg->poolp;
    void* mark = PORT_ArenaMark(poolp);
    OSStatus status = errSecInternal;
    SecAsn1Item etime = { .Data = NULL, .Length = 0 };

    /* create new signing time attribute */
    NSS_Time timeStr;
    if (SecAsn1EncodeTime(poolp, t, &timeStr) != SECSuccess) {
        goto loser;
    }

    if (SEC_ASN1EncodeItem(poolp, &etime, &timeStr, kSecAsn1TimeTemplate) != &etime) {
        goto loser;
    }

    if ((attr = SecCmsAttributeCreate(poolp, SEC_OID_APPLE_EXPIRATION_TIME, &etime, PR_TRUE)) == NULL) {
        goto loser;
    }

    if ((status = SecCmsSignerInfoAddAuthAttr(signerinfo, attr)) != SECSuccess) {
        goto loser;
    }

    PORT_ArenaUnmark(poolp, mark);

    return status;

loser:
    PORT_ArenaRelease(poolp, mark);
    return status;
}

SecCertificateRef SecCmsSignerInfoCopyCertFromEncryptionKeyPreference(SecCmsSignerInfoRef signerinfo)
{
    SecCertificateRef cert = NULL;
    SecCmsAttribute* attr;
    SecAsn1Item* ekp;

    /* see if verification status is ok (unverified does not count...) */
    if (signerinfo->verificationStatus != SecCmsVSGoodSignature)
        return NULL;

    /* Prep the rawCerts */
    SecAsn1Item** rawCerts = NULL;
    if (signerinfo->signedData) {
        rawCerts = signerinfo->signedData->rawCerts;
    }

    /* find preferred encryption cert */
    if (!SecCmsArrayIsEmpty((void**)signerinfo->authAttr) &&
        (attr = SecCmsAttributeArrayFindAttrByOidTag(
             signerinfo->authAttr, SEC_OID_SMIME_ENCRYPTION_KEY_PREFERENCE, PR_TRUE)) !=
            NULL) { /* we have a SMIME_ENCRYPTION_KEY_PREFERENCE attribute! Find the cert. */
        ekp = SecCmsAttributeGetValue(attr);
        if (ekp == NULL) {
            return NULL;
        }
        cert = SecSMIMEGetCertFromEncryptionKeyPreference(rawCerts, ekp);
    }
    if (cert) {
        return cert;
    }

    if (!SecCmsArrayIsEmpty((void**)signerinfo->authAttr) &&
        (attr = SecCmsAttributeArrayFindAttrByOidTag(
             signerinfo->authAttr, SEC_OID_MS_SMIME_ENCRYPTION_KEY_PREFERENCE, PR_TRUE)) !=
            NULL) { /* we have a MS_SMIME_ENCRYPTION_KEY_PREFERENCE attribute! Find the cert. */
        ekp = SecCmsAttributeGetValue(attr);
        if (ekp == NULL) {
            return NULL;
        }
        cert = SecSMIMEGetCertFromEncryptionKeyPreference(rawCerts, ekp);
    }
    return cert;
}

/*
 * XXXX the following needs to be done in the S/MIME layer code
 * after signature of a signerinfo is verified
 */
OSStatus SecCmsSignerInfoSaveSMIMEProfile(SecCmsSignerInfoRef signerinfo)
{
    return -4 /*unImp*/;
}

/*
 * SecCmsSignerInfoIncludeCerts - set cert chain inclusion mode for this signer
 */
OSStatus SecCmsSignerInfoIncludeCerts(SecCmsSignerInfoRef signerinfo, SecCmsCertChainMode cm, SECCertUsage usage)
{
    if (signerinfo->cert == NULL) {
        return SECFailure;
    }

    /* don't leak if we get called twice */
    if (signerinfo->certList != NULL) {
        CFReleaseNull(signerinfo->certList);
    }

    switch (cm) {
        case SecCmsCMNone:
            signerinfo->certList = NULL;
            break;
        case SecCmsCMCertOnly:
            signerinfo->certList = CERT_CertListFromCert(signerinfo->cert);
            break;
        case SecCmsCMCertChain:
            signerinfo->certList =
                CERT_CertChainFromCert(signerinfo->cert, usage, PR_FALSE, PR_FALSE);
            break;
        case SecCmsCMCertChainWithRoot:
            signerinfo->certList = CERT_CertChainFromCert(signerinfo->cert, usage, PR_TRUE, PR_FALSE);
            break;
        case SecCmsCMCertChainWithRootOrFail:
            signerinfo->certList = CERT_CertChainFromCert(signerinfo->cert, usage, PR_TRUE, PR_TRUE);
            break;
    }

    if (cm != SecCmsCMNone && signerinfo->certList == NULL) {
        return SECFailure;
    }

    return SECSuccess;
}
