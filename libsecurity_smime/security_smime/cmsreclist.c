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

#include "cmslocal.h"

#include "SecAsn1Item.h"
#include "cert.h"
#include "secoid.h"

#include <security_asn1/secasn1.h>
#include <security_asn1/secerr.h>
#include <security_asn1/secport.h>

#include <utilities/SecCFWrappers.h>

#include <Security/SecIdentity.h>

static int nss_cms_recipients_traverse(SecCmsRecipientInfoRef* recipientinfos,
                                       SecCmsRecipient** recipient_list)
{
    int count = 0;
    int rlindex = 0;
    int i, j;
    SecCmsRecipient* rle;
    SecCmsRecipientInfoRef ri;
    SecCmsRecipientEncryptedKey* rek;

    for (i = 0; recipientinfos[i] != NULL; i++) {
        ri = recipientinfos[i];
        switch (ri->recipientInfoType) {
            case SecCmsRecipientInfoIDKeyTrans:
                if (recipient_list) {
                    /* alloc one & fill it out */
                    rle = (SecCmsRecipient*)PORT_ZAlloc(sizeof(SecCmsRecipient));
                    if (rle == NULL)
                        return -1;

                    rle->riIndex = i;
                    rle->subIndex = -1;
                    switch (ri->ri.keyTransRecipientInfo.recipientIdentifier.identifierType) {
                        case SecCmsRecipientIDIssuerSN:
                            rle->kind = RLIssuerSN;
                            rle->id.issuerAndSN =
                                ri->ri.keyTransRecipientInfo.recipientIdentifier.id.issuerAndSN;
                            break;
                        case SecCmsRecipientIDSubjectKeyID:
                            rle->kind = RLSubjKeyID;
                            rle->id.subjectKeyID =
                                ri->ri.keyTransRecipientInfo.recipientIdentifier.id.subjectKeyID;
                            break;
                    }
                    recipient_list[rlindex++] = rle;
                } else {
                    count++;
                }
                break;
            case SecCmsRecipientInfoIDKeyAgree:
                if (ri->ri.keyAgreeRecipientInfo.recipientEncryptedKeys == NULL)
                    break;
                for (j = 0; ri->ri.keyAgreeRecipientInfo.recipientEncryptedKeys[j] != NULL; j++) {
                    if (recipient_list) {
                        rek = ri->ri.keyAgreeRecipientInfo.recipientEncryptedKeys[j];
                        /* alloc one & fill it out */
                        rle = (SecCmsRecipient*)PORT_ZAlloc(sizeof(SecCmsRecipient));
                        if (rle == NULL)
                            return -1;

                        rle->riIndex = i;
                        rle->subIndex = j;
                        switch (rek->recipientIdentifier.identifierType) {
                            case SecCmsKeyAgreeRecipientIDIssuerSN:
                                rle->kind = RLIssuerSN;
                                rle->id.issuerAndSN = rek->recipientIdentifier.id.issuerAndSN;
                                break;
                            case SecCmsKeyAgreeRecipientIDRKeyID:
                                rle->kind = RLSubjKeyID;
                                rle->id.subjectKeyID =
                                    &rek->recipientIdentifier.id.recipientKeyIdentifier.subjectKeyIdentifier;
                                break;
                        }
                        recipient_list[rlindex++] = rle;
                    } else {
                        count++;
                    }
                }
                break;
            case SecCmsRecipientInfoIDKEK:
                /* KEK is not implemented */
                break;
        }
    }
    /* if we have a recipient list, we return on success (-1, above, on failure) */
    /* otherwise, we return the count. */
    if (recipient_list) {
        recipient_list[rlindex] = NULL;
        return 0;
    } else {
        return count;
    }
}

SecCmsRecipient** nss_cms_recipient_list_create(SecCmsRecipientInfoRef* recipientinfos)
{
    int count, rv;
    SecCmsRecipient** recipient_list;

    /* count the number of recipient identifiers */
    count = nss_cms_recipients_traverse(recipientinfos, NULL);
    if (count <= 0 || count >= (int)((INT_MAX / sizeof(SecCmsRecipient*)) - 1)) {
        /* no recipients? or risk of underallocation 20130783 */
        PORT_SetError(SEC_ERROR_BAD_DATA);
#if 0
	PORT_SetErrorString("Cannot find recipient data in envelope.");
#endif
        return NULL;
    }

    /* allocate an array of pointers */
    recipient_list = (SecCmsRecipient**)PORT_ZAlloc((size_t)(count + 1) * sizeof(SecCmsRecipient*));
    if (recipient_list == NULL) {
        return NULL;
    }

    /* now fill in the recipient_list */
    rv = nss_cms_recipients_traverse(recipientinfos, recipient_list);
    if (rv < 0) {
        nss_cms_recipient_list_destroy(recipient_list);
        return NULL;
    }
    return recipient_list;
}

void nss_cms_recipient_list_destroy(SecCmsRecipient** recipient_list)
{
    int i;
    SecCmsRecipient* recipient;

    for (i = 0; recipient_list[i] != NULL; i++) {
        recipient = recipient_list[i];
        CFReleaseNull(recipient->cert);
        CFReleaseNull(recipient->privkey);
#if 0
	// @@@ Eliminate slot stuff.
	if (recipient->slot)
	    PK11_FreeSlot(recipient->slot);
#endif
        PORT_Free(recipient);
    }
    PORT_Free(recipient_list);
}

SecCmsRecipientEncryptedKey* SecCmsRecipientEncryptedKeyCreate(PLArenaPool* poolp)
{
    return (SecCmsRecipientEncryptedKey*)PORT_ArenaZAlloc(poolp, sizeof(SecCmsRecipientEncryptedKey));
}


int nss_cms_FindCertAndKeyByRecipientList(SecCmsRecipient** recipient_list, void* wincx)
{
    SecCmsRecipient* recipient = NULL;
    SecCertificateRef cert = NULL;
    SecPrivateKeyRef privKey = NULL;
    SecIdentityRef identity = NULL;
    int ix;
    CFTypeRef keychainOrArray = NULL;  // @@@ The caller should be able to pass this in somehow.

    for (ix = 0; recipient_list[ix] != NULL; ++ix) {
        recipient = recipient_list[ix];

        switch (recipient->kind) {
            case RLIssuerSN:
                identity = CERT_FindIdentityByIssuerAndSN(keychainOrArray, recipient->id.issuerAndSN);
                break;
            case RLSubjKeyID:
                identity = CERT_FindIdentityBySubjectKeyID(keychainOrArray, recipient->id.subjectKeyID);
                break;
        }

        if (identity) {
            break;
        }
    }

    if (!identity) {
        goto loser;
    }

    if (!recipient) {
        goto loser;
    }

    if (SecIdentityCopyCertificate(identity, &cert)) {
        goto loser;
    }
    if (SecIdentityCopyPrivateKey(identity, &privKey)) {
        goto loser;
    }
    CFReleaseNull(identity);

    recipient->cert = cert;
    recipient->privkey = privKey;

    return ix;

loser:
    CFReleaseNull(identity);
    CFReleaseNull(cert);
    CFReleaseNull(privKey);

    return -1;
}
