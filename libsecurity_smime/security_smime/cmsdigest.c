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
 * CMS digesting.
 */
#include <security_utilities/simulatecrash_assert.h>
#include <utilities/debugging.h>

#include "cmslocal.h"

#include "SecAsn1Item.h"
#include "secoid.h"

#include <security_asn1/secerr.h>
#include <security_asn1/secport.h>

#include <CommonCrypto/CommonDigest.h>

#include <Security/SecCmsDigestContext.h>

/* Return the maximum value between S and T and U */
#define MAX_OF_3(S, T, U)                  \
    ({                                     \
        __typeof__(U) _max_st = MAX(S, T); \
        MAX(_max_st, U);                   \
    })

struct SecCmsDigestContextStr {
    PLArenaPool* poolp;
    Boolean saw_contents;
    int digcnt;
    void** digobjs;
    SECAlgorithmID** digestalgs;
};

/*
 * SecCmsDigestContextStartMultiple - start digest calculation using all the
 *  digest algorithms in "digestalgs" in parallel.
 */
SecCmsDigestContextRef SecCmsDigestContextStartMultiple(SECAlgorithmID** digestalgs)
{
    PLArenaPool* poolp;
    SecCmsDigestContextRef cmsdigcx;
    void* digobj;
    int digcnt;
    int i;

    poolp = PORT_NewArena(1024);
    if (poolp == NULL) {
        goto loser;
    }

    digcnt = (digestalgs == NULL) ? 0 : SecCmsArrayCount((void**)digestalgs);

    cmsdigcx = (SecCmsDigestContextRef)PORT_ArenaAlloc(poolp, sizeof(struct SecCmsDigestContextStr));
    if (cmsdigcx == NULL) {
        goto loser;
    }
    cmsdigcx->poolp = poolp;

    if (digcnt > 0) {
        /* Security check to prevent under-allocation */
        if (digcnt >= (int)((INT_MAX / (MAX(sizeof(void*), sizeof(SECAlgorithmID*)))) - 1)) {
            goto loser;
        }
        cmsdigcx->digobjs = (void**)PORT_ArenaAlloc(poolp, (size_t)digcnt * sizeof(void*));
        if (cmsdigcx->digobjs == NULL) {
            goto loser;
        }
        cmsdigcx->digestalgs =
            (SECAlgorithmID**)PORT_ArenaZAlloc(poolp, (size_t)(digcnt + 1) * sizeof(SECAlgorithmID*));
        if (cmsdigcx->digestalgs == NULL) {
            goto loser;
        }
    }

    cmsdigcx->digcnt = 0;

    /*
     * Create a digest object context for each algorithm.
     */
    for (i = 0; i < digcnt; i++) {
        digobj = SecCmsUtilGetHashObjByAlgID(digestalgs[i]);
        /*
         * Skip any algorithm we do not even recognize; obviously,
         * this could be a problem, but if it is critical then the
         * result will just be that the signature does not verify.
         * We do not necessarily want to error out here, because
         * the particular algorithm may not actually be important,
         * but we cannot know that until later.
         */

        cmsdigcx->digobjs[cmsdigcx->digcnt] = digobj;
        cmsdigcx->digestalgs[cmsdigcx->digcnt] = PORT_ArenaAlloc(poolp, sizeof(SECAlgorithmID));
        if (SECITEM_CopyItem(poolp,
                             &(cmsdigcx->digestalgs[cmsdigcx->digcnt]->algorithm),
                             &(digestalgs[i]->algorithm)) ||
            SECITEM_CopyItem(poolp,
                             &(cmsdigcx->digestalgs[cmsdigcx->digcnt]->parameters),
                             &(digestalgs[i]->parameters))) {
            goto loser;
        }
        cmsdigcx->digcnt++;
    }

    cmsdigcx->saw_contents = PR_FALSE;

    return cmsdigcx;

loser:
    if (poolp) {
        PORT_FreeArena(poolp, PR_FALSE);
    }

    return NULL;
}

/*
 * SecCmsDigestContextStartSingle - same as SecCmsDigestContextStartMultiple, but
 *  only one algorithm.
 */
SecCmsDigestContextRef SecCmsDigestContextStartSingle(SECAlgorithmID* digestalg)
{
    SECAlgorithmID* digestalgs[] = {NULL, NULL}; /* fake array */

    digestalgs[0] = digestalg;
    return SecCmsDigestContextStartMultiple(digestalgs);
}

/*
 * SecCmsDigestContextUpdate - feed more data into the digest machine
 */
void SecCmsDigestContextUpdate(SecCmsDigestContextRef cmsdigcx, const unsigned char* data, size_t len)
{
    /* rdar://problem/20642513. There is really no good way to return an error here, so let's just
       exit without having "seen" any contents. This should cause hash comparisons to fail during
       validation.
     */
    if (len > UINT32_MAX) {
        secerror("SecCmsDigestContextUpdate: data size too big (%zu), skipping", len);
        return;
    }

    int i;
    cmsdigcx->saw_contents = PR_TRUE;
    for (i = 0; i < cmsdigcx->digcnt; i++) {
        if (cmsdigcx->digobjs[i]) {
            assert(len <= UINT32_MAX); /* Debug check. Correct as long as CC_LONG is uint32_t */
            switch (SECOID_GetAlgorithmTag(cmsdigcx->digestalgs[i])) {
                case SEC_OID_SHA1:
                    CC_SHA1_Update((CC_SHA1_CTX*)cmsdigcx->digobjs[i], data, (CC_LONG)len);
                    break;
                case SEC_OID_MD5:
                    CC_MD5_Update((CC_MD5_CTX*)cmsdigcx->digobjs[i], data, (CC_LONG)len);
                    break;
                case SEC_OID_SHA224:
                    CC_SHA224_Update((CC_SHA256_CTX*)cmsdigcx->digobjs[i], data, (CC_LONG)len);
                    break;
                case SEC_OID_SHA256:
                    CC_SHA256_Update((CC_SHA256_CTX*)cmsdigcx->digobjs[i], data, (CC_LONG)len);
                    break;
                case SEC_OID_SHA384:
                    CC_SHA384_Update((CC_SHA512_CTX*)cmsdigcx->digobjs[i], data, (CC_LONG)len);
                    break;
                case SEC_OID_SHA512:
                    CC_SHA512_Update((CC_SHA512_CTX*)cmsdigcx->digobjs[i], data, (CC_LONG)len);
                    break;
                default:
                    break;
            }
        }
    }
}

/*
 * SecCmsDigestContextCancel - cancel digesting operation
 */
void SecCmsDigestContextCancel(SecCmsDigestContextRef cmsdigcx)
{
    int i;

    for (i = 0; i < cmsdigcx->digcnt; i++) {
        if (cmsdigcx->digobjs && cmsdigcx->digobjs[i]) {
            free(cmsdigcx->digobjs[i]);
            cmsdigcx->digobjs[i] = NULL;
        }
    }

    PORT_FreeArena(cmsdigcx->poolp, PR_TRUE);
}

/*
 * SecCmsDigestContextDestroy - delete a digesting operation
 */
void SecCmsDigestContextDestroy(SecCmsDigestContextRef cmsdigcx)
{
    SecCmsDigestContextCancel(cmsdigcx);
}

/*
 * SecCmsDigestContextFinishMultiple - finish the digests
 * Note that on iOS, this call only frees the digest objects and requires a call to SecCmsDisgestContextDestroy
 * or SecCmsDisgestContextCancel (because the digests are allocated out of the context's pool).
 * The macOS version cancels and frees the digest context (because the digests are allocated from an input arena pool).
 */
OSStatus SecCmsDigestContextFinishMultiple(SecCmsDigestContextRef cmsdigcx,
                                           SECAlgorithmID*** digestalgsp,
                                           SecAsn1Item*** digestsp)
{
    void* digobj;
    SecAsn1Item **digests, *digest;
    SECAlgorithmID** digestalgs;
    int i;
    void* mark;
    OSStatus rv = SECFailure;

    assert(cmsdigcx != NULL);

    /* A message with no contents (just signed attributes) is used within SCEP */
    assert(digestsp != NULL);
    assert(digestalgsp != NULL);

    mark = PORT_ArenaMark(cmsdigcx->poolp);

    /* Security check to prevent under-allocation */
    if (cmsdigcx->digcnt >=
        (int)((INT_MAX / (MAX_OF_3(sizeof(SECAlgorithmID*), sizeof(SecAsn1Item*), sizeof(SecAsn1Item)))) - 1)) {
        goto loser;
    }
    /* allocate digest array & SecAsn1Items on arena */
    digestalgs = (SECAlgorithmID**)PORT_ArenaZAlloc(
        cmsdigcx->poolp, (size_t)(cmsdigcx->digcnt + 1) * sizeof(SECAlgorithmID*));
    digests = (SecAsn1Item**)PORT_ArenaZAlloc(cmsdigcx->poolp,
                                              (size_t)(cmsdigcx->digcnt + 1) * sizeof(SecAsn1Item*));
    digest = (SecAsn1Item*)PORT_ArenaZAlloc(cmsdigcx->poolp, (size_t)cmsdigcx->digcnt * sizeof(SecAsn1Item));
    if (digestalgs == NULL || digests == NULL || digest == NULL) {
        goto loser;
    }

    for (i = 0; i < cmsdigcx->digcnt; i++, digest++) {
        SECOidTag hash_alg = SECOID_GetAlgorithmTag(cmsdigcx->digestalgs[i]);
        size_t diglength = 0;

        switch (hash_alg) {
            case SEC_OID_SHA1:
                diglength = CC_SHA1_DIGEST_LENGTH;
                break;
            case SEC_OID_MD5:
                diglength = CC_MD5_DIGEST_LENGTH;
                break;
            case SEC_OID_SHA224:
                diglength = CC_SHA224_DIGEST_LENGTH;
                break;
            case SEC_OID_SHA256:
                diglength = CC_SHA256_DIGEST_LENGTH;
                break;
            case SEC_OID_SHA384:
                diglength = CC_SHA384_DIGEST_LENGTH;
                break;
            case SEC_OID_SHA512:
                diglength = CC_SHA512_DIGEST_LENGTH;
                break;
            default:
                goto loser;
        }

        digobj = cmsdigcx->digobjs[i];
        if (digobj) {
            digest->Data = (unsigned char*)PORT_ArenaAlloc(cmsdigcx->poolp, diglength);
            if (digest->Data == NULL)
                goto loser;
            digest->Length = diglength;
            switch (hash_alg) {
                case SEC_OID_SHA1:
                    CC_SHA1_Final(digest->Data, digobj);
                    break;
                case SEC_OID_MD5:
                    CC_MD5_Final(digest->Data, digobj);
                    break;
                case SEC_OID_SHA224:
                    CC_SHA224_Final(digest->Data, digobj);
                    break;
                case SEC_OID_SHA256:
                    CC_SHA256_Final(digest->Data, digobj);
                    break;
                case SEC_OID_SHA384:
                    CC_SHA384_Final(digest->Data, digobj);
                    break;
                case SEC_OID_SHA512:
                    CC_SHA512_Final(digest->Data, digobj);
                    break;
                default:
                    goto loser;
            }

            free(digobj);
            digestalgs[i] = cmsdigcx->digestalgs[i];
            digests[i] = digest;
        } else {
            digest->Data = NULL;
            digest->Length = 0;
        }
    }
    digestalgs[i] = NULL;
    digests[i] = NULL;
    *digestalgsp = digestalgs;
    *digestsp = digests;

    rv = SECSuccess;

loser:
    if (rv == SECSuccess) {
        PORT_ArenaUnmark(cmsdigcx->poolp, mark);
    } else {
        PORT_ArenaRelease(cmsdigcx->poolp, mark);
    }

    /*cleanup:*/
    /* Set things up so SecCmsDigestContextDestroy won't call CSSM_DeleteContext again. */
    cmsdigcx->digcnt = 0;

    return rv;
}

/*
 * SecCmsDigestContextFinishSingle - same as SecCmsDigestContextFinishMultiple,
 *  but for one digest.
 */
OSStatus SecCmsDigestContextFinishSingle(SecCmsDigestContextRef cmsdigcx, SecAsn1Item* digest)
{
    OSStatus rv = SECFailure;
    SecAsn1Item** dp;
    SECAlgorithmID** ap;

    /* get the digests into arena, then copy the first digest into poolp */
    if (SecCmsDigestContextFinishMultiple(cmsdigcx, &ap, &dp) != SECSuccess) {
        goto loser;
    }

    /* Return the first element in the digest array. */
    if (digest) {
        *digest = *dp[0];
    }

    rv = SECSuccess;

loser:
    return rv;
}
