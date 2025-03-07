/*
 * Copyright (c) 2000-2004,2008,2010,2012-2015 Apple Inc. All Rights Reserved.
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
 * oidsalg.c - OIDs defining crypto algorithms
 */

#include <Security/oidsbase.h>
#include <stdint.h>
#include "SecAsn1Types.h"

static const uint8_t OID_MD2[] = {OID_RSA_HASH, 2}, OID_MD4[] = {OID_RSA_HASH, 4},
                     OID_MD5[] = {OID_RSA_HASH, 5}, OID_RSAEncryption[] = {OID_PKCS_1, 1},
                     OID_MD2WithRSA[] = {OID_PKCS_1, 2}, OID_MD4WithRSA[] = {OID_PKCS_1, 3},
                     OID_MD5WithRSA[] = {OID_PKCS_1, 4}, OID_SHA1WithRSA[] = {OID_PKCS_1, 5},
                     OID_RSAWithOAEP[] = {OID_PKCS_1, 7}, OID_OAEP_MGF1[] = {OID_PKCS_1, 8},
                     OID_OAEP_ID_PSPECIFIED[] = {OID_PKCS_1, 9},
                     OID_SHA224WithRSA[] = {OID_PKCS_1, 14},
                     OID_SHA256WithRSA[] = {OID_PKCS_1, 11},
                     OID_SHA384WithRSA[] = {OID_PKCS_1, 12},
                     OID_SHA512WithRSA[] = {OID_PKCS_1, 13},
                     OID_PKCS_3_ARC[] = {OID_PKCS_3}, OID_DHKeyAgreement[] = {OID_PKCS_3, 1},
                     /* BSAFE-specific DSA */
    OID_OIW_DSA[] = {OID_OIW_ALGORITHM, 12}, OID_OIW_DSAWithSHA1[] = {OID_OIW_ALGORITHM, 27},
                     /* DSA from CMS */
    OID_CMS_DSA[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 4, 1},
                     OID_CMS_DSAWithSHA1[] = {0x2A, 0x86, 0x48, 0xCE, 0x38, 4, 3},
                     /* DSA from JDK 1.1 */
    OID_JDK_DSA[] = {0x2B, 0x0E, 0x03, 0x02, 0x0c},
                     OID_JDK_DSAWithSHA1[] = {0x2B, 0x0E, 0x03, 0x02, 0x0D},

                     OID_OIW_SHA1[] = {OID_OIW_ALGORITHM, 26},
                     OID_OIW_RSAWithSHA1[] = {OID_OIW_ALGORITHM, 29},
                     OID_OIW_DES_CBC[] = {OID_OIW_ALGORITHM, 7},

                     OID_SHA224[] = {OID_NIST_HASHALG, 4}, OID_SHA256[] = {OID_NIST_HASHALG, 1},
                     OID_SHA384[] = {OID_NIST_HASHALG, 2}, OID_SHA512[] = {OID_NIST_HASHALG, 3},

                     /* ANSI X9.42 */
    OID_ANSI_DH_PUB_NUMBER[] = {OID_ANSI_X9_42, 1},
                     OID_ANSI_DH_STATIC[] = {OID_ANSI_X9_42_SCHEME, 1},
                     OID_ANSI_DH_EPHEM[] = {OID_ANSI_X9_42_SCHEME, 2},
                     OID_ANSI_DH_ONE_FLOW[] = {OID_ANSI_X9_42_SCHEME, 3},
                     OID_ANSI_DH_HYBRID1[] = {OID_ANSI_X9_42_SCHEME, 4},
                     OID_ANSI_DH_HYBRID2[] = {OID_ANSI_X9_42_SCHEME, 5},
                     OID_ANSI_DH_HYBRID_ONEFLOW[] = {OID_ANSI_X9_42_SCHEME, 6},
                     /* sic - enumerated in reverse order in the spec */
    OID_ANSI_MQV1[] = {OID_ANSI_X9_42_SCHEME, 8}, OID_ANSI_MQV2[] = {OID_ANSI_X9_42_SCHEME, 7},

                     OID_ANSI_DH_STATIC_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 1},
                     OID_ANSI_DH_EPHEM_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 2},
                     OID_ANSI_DH_ONE_FLOW_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 3},
                     OID_ANSI_DH_HYBRID1_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 4},
                     OID_ANSI_DH_HYBRID2_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 5},
                     OID_ANSI_DH_HYBRID_ONEFLOW_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 6},
                     /* sic - enumerated in reverse order in the spec */
    OID_ANSI_MQV1_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 8},
                     OID_ANSI_MQV2_SHA1[] = {OID_ANSI_X9_42_NAMED_SCHEME, 7};

const SecAsn1Oid
    CSSMOID_MD2 = {OID_RSA_HASH_LENGTH + 1, (uint8_t*)OID_MD2},
    CSSMOID_MD4 = {OID_RSA_HASH_LENGTH + 1, (uint8_t*)OID_MD4},
    CSSMOID_MD5 = {OID_RSA_HASH_LENGTH + 1, (uint8_t*)OID_MD5},
    CSSMOID_RSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_RSAEncryption},
    CSSMOID_MD2WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_MD2WithRSA},
    CSSMOID_MD4WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_MD4WithRSA},
    CSSMOID_MD5WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_MD5WithRSA},
    CSSMOID_SHA1WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_SHA1WithRSA},
    CSSMOID_RSAWithOAEP = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_RSAWithOAEP},
    CSSMOID_OAEP_MGF1 = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_OAEP_MGF1},
    CSSMOID_OAEP_ID_PSPECIFIED = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_OAEP_ID_PSPECIFIED},
    CSSMOID_SHA224WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_SHA224WithRSA},
    CSSMOID_SHA256WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_SHA256WithRSA},
    CSSMOID_SHA384WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_SHA384WithRSA},
    CSSMOID_SHA512WithRSA = {OID_PKCS_1_LENGTH + 1, (uint8_t*)OID_SHA512WithRSA},
    CSSMOID_PKCS3 = {OID_PKCS_3_LENGTH, (uint8_t*)OID_PKCS_3_ARC},
    CSSMOID_DH = {OID_PKCS_3_LENGTH + 1, (uint8_t*)OID_DHKeyAgreement},
    CSSMOID_DSA = {OID_OIW_ALGORITHM_LENGTH + 1, (uint8_t*)OID_OIW_DSA},
    CSSMOID_DSA_CMS = {7, (uint8_t*)OID_CMS_DSA}, CSSMOID_DSA_JDK = {5, (uint8_t*)OID_JDK_DSA},
    CSSMOID_SHA1WithDSA = {OID_OIW_ALGORITHM_LENGTH + 1, (uint8_t*)OID_OIW_DSAWithSHA1},
    CSSMOID_SHA1WithDSA_CMS = {7, (uint8_t*)OID_CMS_DSAWithSHA1},
    CSSMOID_SHA1WithDSA_JDK = {5, (uint8_t*)OID_JDK_DSAWithSHA1},
    CSSMOID_SHA1 = {OID_OIW_ALGORITHM_LENGTH + 1, (uint8_t*)OID_OIW_SHA1},
    CSSMOID_SHA224 = {OID_NIST_HASHALG_LENGTH + 1, (uint8_t*)OID_SHA224},
    CSSMOID_SHA256 = {OID_NIST_HASHALG_LENGTH + 1, (uint8_t*)OID_SHA256},
    CSSMOID_SHA384 = {OID_NIST_HASHALG_LENGTH + 1, (uint8_t*)OID_SHA384},
    CSSMOID_SHA512 = {OID_NIST_HASHALG_LENGTH + 1, (uint8_t*)OID_SHA512},
    CSSMOID_SHA1WithRSA_OIW = {OID_OIW_ALGORITHM_LENGTH + 1, (uint8_t*)OID_OIW_RSAWithSHA1},
    CSSMOID_DES_CBC = {OID_OIW_ALGORITHM_LENGTH + 1, (uint8_t*)OID_OIW_DES_CBC},
    CSSMOID_ANSI_DH_PUB_NUMBER = {OID_ANSI_X9_42_LEN + 1, (uint8_t*)OID_ANSI_DH_PUB_NUMBER},
    CSSMOID_ANSI_DH_STATIC = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_STATIC},
    CSSMOID_ANSI_DH_ONE_FLOW = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_ONE_FLOW},
    CSSMOID_ANSI_DH_EPHEM = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_EPHEM},
    CSSMOID_ANSI_DH_HYBRID1 = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_HYBRID1},
    CSSMOID_ANSI_DH_HYBRID2 = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_HYBRID2},
    CSSMOID_ANSI_DH_HYBRID_ONEFLOW = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_HYBRID_ONEFLOW},
    CSSMOID_ANSI_MQV1 = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_MQV1},
    CSSMOID_ANSI_MQV2 = {OID_ANSI_X9_42_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_MQV2},
    CSSMOID_ANSI_DH_STATIC_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_STATIC_SHA1},
    CSSMOID_ANSI_DH_ONE_FLOW_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1,
                                     (uint8_t*)OID_ANSI_DH_ONE_FLOW_SHA1},
    CSSMOID_ANSI_DH_EPHEM_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_EPHEM_SHA1},
    CSSMOID_ANSI_DH_HYBRID1_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_HYBRID1_SHA1},
    CSSMOID_ANSI_DH_HYBRID2_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_DH_HYBRID2_SHA1},
    CSSMOID_ANSI_DH_HYBRID_ONEFLOW_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1,
                                           (uint8_t*)OID_ANSI_DH_HYBRID_ONEFLOW_SHA1},
    CSSMOID_ANSI_MQV1_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_MQV1_SHA1},
    CSSMOID_ANSI_MQV2_SHA1 = {OID_ANSI_X9_42_NAMED_SCHEME_LEN + 1, (uint8_t*)OID_ANSI_MQV2_SHA1};


/*	iSignTP OBJECT IDENTIFIER ::=
 *		{ appleTrustPolicy 1 }
 *      { 1 2 840 113635 100 1 1 }
 *
 * BER =  06 09 2A 86 48 86 F7 63 64 01 01
 */
static const uint8_t
    APPLE_TP_ISIGN[] = {APPLE_TP_OID, 1},

    /*	AppleX509Basic OBJECT IDENTIFIER ::=
 *		{ appleTrustPolicy 2 }
 *      { 1 2 840 113635 100 1 2 }
 *
 * BER =  06 09 2A 86 48 86 F7 63 64 01 01
 */
    APPLE_TP_X509_BASIC[] = {APPLE_TP_OID, 2},

    /* AppleSSLPolicy := {appleTrustPolicy 3 } */
    APPLE_TP_SSL[] = {APPLE_TP_OID, 3},

    /* AppleLocalCertGenPolicy := {appleTrustPolicy 4 } */
    APPLE_TP_LOCAL_CERT_GEN[] = {APPLE_TP_OID, 4},

    /* AppleCSRGenPolicy := {appleTrustPolicy 5 } */
    APPLE_TP_CSR_GEN[] = {APPLE_TP_OID, 5},

    /* Apple CRL-based revocation policy := {appleTrustPolicy 6 } */
    APPLE_TP_REVOCATION_CRL[] = {APPLE_TP_OID, 6},

    /* Apple OCSP-based revocation policy := {appleTrustPolicy 7 } */
    APPLE_TP_REVOCATION_OCSP[] = {APPLE_TP_OID, 7},

    /* Apple S/MIME trust policy := {appleTrustPolicy 8 } */
    APPLE_TP_SMIME[] = {APPLE_TP_OID, 8},

    /* Apple EAP trust policy := {appleTrustPolicy 9 } */
    APPLE_TP_EAP[] = {APPLE_TP_OID, 9},

    /*
 * NOTE: "Apple Code Signing Policy", CSSMOID_APPLE_TP_CODE_SIGN, was renamed
 * to "Apple Software Update Signing Policy", CSSMOID_APPLE_TP_SW_UPDATE_SIGNING,
 * on 8/16/06. For compatibility, we keep the TP_CODE_SIGN OID here until
 * SoftwareUpdate converts to the new symbol.
 *
 * Apple Code Signing Policy := { appleTrustPolicy 10 }
 * Apple Software Update Signing Policy := { appleTrustPolicy 10 }
 */
    APPLE_SW_UPDATE_SIGNING[] = {APPLE_TP_OID, 10},
#define APPLE_TP_CODE_SIGN APPLE_SW_UPDATE_SIGNING

    /* Apple IPSec Policy := { appleTrustPolicy 11 } */
    APPLE_TP_IP_SEC[] = {APPLE_TP_OID, 11},

    /* Apple iChat Policy := { appleTrustPolicy 12 } */
    APPLE_TP_ICHAT[] = {APPLE_TP_OID, 12},

    /* Apple Resource Signing Policy := { appleTrustPolicy 13 } */
    APPLE_TP_RESOURCE_SIGN[] = {APPLE_TP_OID, 13},

    /* Apple PKINIT Client Cert Policy := { appleTrustPolicy 14 } */
    APPLE_TP_PKINIT_CLIENT[] = {APPLE_TP_OID, 14},

    /* Apple PKINIT Server Cert Policy := { appleTrustPolicy 15 } */
    APPLE_TP_PKINIT_SERVER[] = {APPLE_TP_OID, 15},

    /* Apple Code Signing Cert Policy := { appleTrustPolicy 16 } */
    APPLE_TP_CODE_SIGNING[] = {APPLE_TP_OID, 16},

    /* Apple Package Signing Cert Policy := { appleTrustPolicy 17 } */
    APPLE_TP_PACKAGE_SIGNING[] = {APPLE_TP_OID, 17},

    /* AppleID Sharing Cert Policy := { appleTrustPolicy 18 } */
    APPLE_TP_APPLEID_SHARING[] = {APPLE_TP_OID, 18},
    /* appleIDValidationPolicy */

    /* Apple MacAppStore receipt verification policy := { appleTrustPolicy 19 } */
    APPLE_TP_MACAPPSTORE_RECEIPT[] = {APPLE_TP_OID, 19},

    /* Apple Time Stamping Server Cert Policy := { appleTrustPolicy 20 } */
    APPLE_TP_TIMESTAMPING[] = {APPLE_TP_OID, 20},

    /* Apple Revocation Policy := { appleTrustPolicy 21 } */
    APPLE_TP_REVOCATION[] = {APPLE_TP_OID, 21},

    /* Apple Passbook Signing Policy := { appleTrustPolicy 22 } */
    APPLE_TP_PASSBOOK_SIGNING[] = {APPLE_TP_OID, 22},

    /* Apple Mobile Store Policy := { appleTrustPolicy 23 } */
    APPLE_TP_MOBILE_STORE[] = {APPLE_TP_OID, 23},

    /* Apple Escrow Service Policy := { appleTrustPolicy 24 } */
    APPLE_TP_ESCROW_SERVICE[] = {APPLE_TP_OID, 24},

    /* Apple Configuration Profile Signing Policy := { appleTrustPolicy 25 } */
    APPLE_TP_PROFILE_SIGNING[] = {APPLE_TP_OID, 25},

    /* Apple QA Configuration Profile Signing Policy := { appleTrustPolicy 26 } */
    APPLE_TP_QA_PROFILE_SIGNING[] = {APPLE_TP_OID, 26},

    /* Apple Test Mobile Store Policy := { appleTrustPolicy 27 } */
    APPLE_TP_TEST_MOBILE_STORE[] = {APPLE_TP_OID, 27},

    /* Apple PCS Escrow Service Policy := { appleTrustPolicy 34 } */
    APPLE_TP_PCS_ESCROW_SERVICE[] = {APPLE_TP_OID, 34},

    /* Apple OS X Provisioning Profile Signing := { appleTrustPolicy, 40 } */
    APPLE_TP_PROVISIONING_PROFILE_SIGNING[] = {APPLE_TP_OID, 40},

    /*
 *	fee OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 1 }
 *      { 1 2 840 113635 100 2 1 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 01
 */
    APPLE_FEE[] = {APPLE_ALG_OID, 1},

    /*
 *	asc OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 2 }
 *      { 1 2 840 113635 100 2 2 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 02
 */
    APPLE_ASC[] = {APPLE_ALG_OID, 2},

    /*
 *	fee_MD5 OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 3 }
 *      { 1 2 840 113635 100 2 3 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 03
 */
    APPLE_FEE_MD5[] = {APPLE_ALG_OID, 3},

    /*
 *	fee_SHA1 OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 4 }
 *      { 1 2 840 113635 100 2 4 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 04
 */
    APPLE_FEE_SHA1[] = {APPLE_ALG_OID, 4},

    /*
 *	feed OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 5 }
 *      { 1 2 840 113635 100 2 5 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 05
 */
    APPLE_FEED[] = {APPLE_ALG_OID, 5},

    /*
 *	feedExp OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 6 }
 *      { 1 2 840 113635 100 2 6 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 06
 */
    APPLE_FEEDEXP[] = {APPLE_ALG_OID, 6},

    /*
 *	AppleECDSA OBJECT IDENTIFIER ::=
 *		{ appleSecurityAlgorithm 7 }
 *      { 1 2 840 113635 100 2 7 }
 *
 * BER = 06 09 2A 86 48 86 F7 63 64 02 07
 */
    APPLE_ECDSA[] = {APPLE_ALG_OID, 7},

    /* .mac cert OIDs */
    OID_DOTMAC_CERT[] = {APPLE_DOTMAC_CERT_OID},
    OID_DOTMAC_CERT_REQ[] = {APPLE_DOTMAC_CERT_REQ_OID},
    OID_DOTMAC_CERT_REQ_IDENTITY[] = {APPLE_DOTMAC_CERT_REQ_OID, 1},      /* deprecated */
    OID_DOTMAC_CERT_REQ_EMAIL_SIGN[] = {APPLE_DOTMAC_CERT_REQ_OID, 2},    /* deprecated */
    OID_DOTMAC_CERT_REQ_EMAIL_ENCRYPT[] = {APPLE_DOTMAC_CERT_REQ_OID, 3}, /* deprecated */
    OID_DOTMAC_CERT_REQ_ARCHIVE_LIST[] = {APPLE_DOTMAC_CERT_REQ_OID, 4},
    OID_DOTMAC_CERT_REQ_ARCHIVE_STORE[] = {APPLE_DOTMAC_CERT_REQ_OID, 5},
    OID_DOTMAC_CERT_REQ_ARCHIVE_FETCH[] = {APPLE_DOTMAC_CERT_REQ_OID, 6},
    OID_DOTMAC_CERT_REQ_ARCHIVE_REMOVE[] = {APPLE_DOTMAC_CERT_REQ_OID, 7},
    OID_DOTMAC_CERT_REQ_SHARED_SERVICES[] = {APPLE_DOTMAC_CERT_REQ_OID, 8}, /* treadstone - Shared Services */

    /* OIDs for specifying OID/values pairs in a cert request */
    OID_DOTMAC_CERT_REQ_VALUE_USERNAME[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 1},
    OID_DOTMAC_CERT_REQ_VALUE_PASSWORD[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 2},
    OID_DOTMAC_CERT_REQ_VALUE_HOSTNAME[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 3},
    OID_DOTMAC_CERT_REQ_VALUE_RENEW[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 4},
    OID_DOTMAC_CERT_REQ_VALUE_ASYNC[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 5},
    OID_DOTMAC_CERT_REQ_VALUE_IS_PENDING[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 6},
    __unused OID_DOTMAC_CERT_REQ_VALUE_TYPE_ICHAT[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 7},
    __unused OID_DOTMAC_CERT_REQ_VALUE_TYPE_SHARED_SERVICE[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 8},
    __unused OID_DOTMAC_CERT_REQ_VALUE_TYPE_EMAIL_ENCRYPT[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 9},
    __unused OID_DOTMAC_CERT_REQ_VALUE_TYPE_EMAIL_SIGN[] = {APPLE_DOTMAC_CERT_REQ_VALUE_OID, 10};

const SecAsn1Oid

    CSSMOID_APPLE_ISIGN = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_ISIGN},
    CSSMOID_APPLE_X509_BASIC = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_X509_BASIC},
    CSSMOID_APPLE_TP_SSL = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_SSL},
    CSSMOID_APPLE_TP_LOCAL_CERT_GEN = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_LOCAL_CERT_GEN},
    CSSMOID_APPLE_TP_CSR_GEN = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_CSR_GEN},
    CSSMOID_APPLE_TP_REVOCATION_CRL = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_REVOCATION_CRL},
    CSSMOID_APPLE_TP_REVOCATION_OCSP = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_REVOCATION_OCSP},
    CSSMOID_APPLE_TP_SMIME = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_SMIME},
    CSSMOID_APPLE_TP_EAP = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_EAP},
    /* CSSMOID_APPLE_TP_CODE_SIGN here for temporary compatibility */
    CSSMOID_APPLE_TP_CODE_SIGN = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_CODE_SIGN},
    CSSMOID_APPLE_TP_SW_UPDATE_SIGNING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_SW_UPDATE_SIGNING},
    CSSMOID_APPLE_TP_IP_SEC = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_IP_SEC},
    CSSMOID_APPLE_TP_ICHAT = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_ICHAT},
    CSSMOID_APPLE_TP_RESOURCE_SIGN = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_RESOURCE_SIGN},
    CSSMOID_APPLE_TP_PKINIT_CLIENT = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_PKINIT_CLIENT},
    CSSMOID_APPLE_TP_PKINIT_SERVER = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_PKINIT_SERVER},
    CSSMOID_APPLE_TP_CODE_SIGNING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_CODE_SIGNING},
    CSSMOID_APPLE_TP_PACKAGE_SIGNING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_PACKAGE_SIGNING},
    CSSMOID_APPLE_TP_MACAPPSTORE_RECEIPT = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_MACAPPSTORE_RECEIPT},
    CSSMOID_APPLE_TP_APPLEID_SHARING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_APPLEID_SHARING},
    CSSMOID_APPLE_TP_TIMESTAMPING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_TIMESTAMPING},
    CSSMOID_APPLE_TP_REVOCATION = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_REVOCATION},
    CSSMOID_APPLE_TP_PASSBOOK_SIGNING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_PASSBOOK_SIGNING},
    CSSMOID_APPLE_TP_MOBILE_STORE = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_MOBILE_STORE},
    CSSMOID_APPLE_TP_ESCROW_SERVICE = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_ESCROW_SERVICE},
    CSSMOID_APPLE_TP_PROFILE_SIGNING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_PROFILE_SIGNING},
    CSSMOID_APPLE_TP_QA_PROFILE_SIGNING = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_QA_PROFILE_SIGNING},
    CSSMOID_APPLE_TP_TEST_MOBILE_STORE = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_TEST_MOBILE_STORE},
    CSSMOID_APPLE_TP_PCS_ESCROW_SERVICE = {APPLE_TP_OID_LENGTH + 1, (uint8_t*)APPLE_TP_PCS_ESCROW_SERVICE},
    CSSMOID_APPLE_TP_PROVISIONING_PROFILE_SIGNING = {APPLE_TP_OID_LENGTH + 1,
                                                     (uint8_t*)APPLE_TP_PROVISIONING_PROFILE_SIGNING},
    CSSMOID_APPLE_FEE = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_FEE},
    CSSMOID_APPLE_ASC = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_ASC},
    CSSMOID_APPLE_FEE_MD5 = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_FEE_MD5},
    CSSMOID_APPLE_FEE_SHA1 = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_FEE_SHA1},
    CSSMOID_APPLE_FEED = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_FEED},
    CSSMOID_APPLE_FEEDEXP = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_FEEDEXP},
    CSSMOID_APPLE_ECDSA = {APPLE_ALG_OID_LENGTH + 1, (uint8_t*)APPLE_ECDSA},
    /* .mac cert OIDs */
    CSSMOID_DOTMAC_CERT = {APPLE_DOTMAC_CERT_OID_LENGTH, (uint8_t*)OID_DOTMAC_CERT},
    CSSMOID_DOTMAC_CERT_REQ = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH, (uint8_t*)OID_DOTMAC_CERT_REQ},
    /* This actually used to be for requesting an encrypted iChat cert; deprecated in Leopard */
    CSSMOID_DOTMAC_CERT_REQ_IDENTITY = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                        (uint8_t*)OID_DOTMAC_CERT_REQ_IDENTITY},
    CSSMOID_DOTMAC_CERT_REQ_EMAIL_SIGN = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                          (uint8_t*)OID_DOTMAC_CERT_REQ_EMAIL_SIGN},
    CSSMOID_DOTMAC_CERT_REQ_EMAIL_ENCRYPT = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                             (uint8_t*)OID_DOTMAC_CERT_REQ_EMAIL_ENCRYPT},
    CSSMOID_DOTMAC_CERT_REQ_ARCHIVE_LIST = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                            (uint8_t*)OID_DOTMAC_CERT_REQ_ARCHIVE_LIST},
    CSSMOID_DOTMAC_CERT_REQ_ARCHIVE_STORE = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                             (uint8_t*)OID_DOTMAC_CERT_REQ_ARCHIVE_STORE},
    CSSMOID_DOTMAC_CERT_REQ_ARCHIVE_FETCH = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                             (uint8_t*)OID_DOTMAC_CERT_REQ_ARCHIVE_FETCH},
    CSSMOID_DOTMAC_CERT_REQ_ARCHIVE_REMOVE = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                              (uint8_t*)OID_DOTMAC_CERT_REQ_ARCHIVE_REMOVE},
    CSSMOID_DOTMAC_CERT_REQ_SHARED_SERVICES = {APPLE_DOTMAC_CERT_REQ_OID_LENGTH + 1,
                                               (uint8_t*)OID_DOTMAC_CERT_REQ_SHARED_SERVICES},
    CSSMOID_DOTMAC_CERT_REQ_VALUE_USERNAME = {APPLE_DOTMAC_CERT_REQ_VALUE_OID_LENGTH + 1,
                                              (uint8_t*)OID_DOTMAC_CERT_REQ_VALUE_USERNAME},
    CSSMOID_DOTMAC_CERT_REQ_VALUE_PASSWORD = {APPLE_DOTMAC_CERT_REQ_VALUE_OID_LENGTH + 1,
                                              (uint8_t*)OID_DOTMAC_CERT_REQ_VALUE_PASSWORD},
    CSSMOID_DOTMAC_CERT_REQ_VALUE_HOSTNAME = {APPLE_DOTMAC_CERT_REQ_VALUE_OID_LENGTH + 1,
                                              (uint8_t*)OID_DOTMAC_CERT_REQ_VALUE_HOSTNAME},
    CSSMOID_DOTMAC_CERT_REQ_VALUE_RENEW = {APPLE_DOTMAC_CERT_REQ_VALUE_OID_LENGTH + 1,
                                           (uint8_t*)OID_DOTMAC_CERT_REQ_VALUE_RENEW},
    CSSMOID_DOTMAC_CERT_REQ_VALUE_ASYNC = {APPLE_DOTMAC_CERT_REQ_VALUE_OID_LENGTH + 1,
                                           (uint8_t*)OID_DOTMAC_CERT_REQ_VALUE_ASYNC},
    CSSMOID_DOTMAC_CERT_REQ_VALUE_IS_PENDING = {APPLE_DOTMAC_CERT_REQ_VALUE_OID_LENGTH + 1,
                                                (uint8_t*)OID_DOTMAC_CERT_REQ_VALUE_IS_PENDING};

/* PKCS5 algorithms */

static const uint8_t OID_PKCS5_DIGEST_ALG[] = {OID_RSA_HASH},
                     OID_PKCS5_ENCRYPT_ALG[] = {OID_RSA_ENCRYPT},
                     OID_PKCS5_HMAC_SHA1[] = {OID_RSA_HASH, 7},
                     OID_PKCS5_pbeWithMD2AndDES[] = {OID_PKCS_5, 1},
                     OID_PKCS5_pbeWithMD5AndDES[] = {OID_PKCS_5, 3},
                     OID_PKCS5_pbeWithMD2AndRC2[] = {OID_PKCS_5, 4},
                     OID_PKCS5_pbeWithMD5AndRC2[] = {OID_PKCS_5, 6},
                     OID_PKCS5_pbeWithSHA1AndDES[] = {OID_PKCS_5, 10},
                     OID_PKCS5_pbeWithSHA1AndRC2[] = {OID_PKCS_5, 11},
                     OID_PKCS5_PBKDF2[] = {OID_PKCS_5, 12},
                     OID_PKCS5_PBES2[] = {OID_PKCS_5, 13}, OID_PKCS5_PBMAC1[] = {OID_PKCS_5, 14},
                     OID_PKCS5_RC2_CBC[] = {OID_RSA_ENCRYPT, 2},
                     OID_PKCS5_DES_EDE3_CBC[] = {OID_RSA_ENCRYPT, 7},
                     OID_PKCS5_RC5_CBC[] = {OID_RSA_ENCRYPT, 9};

const SecAsn1Oid
    CSSMOID_PKCS5_DIGEST_ALG = {OID_RSA_HASH_LENGTH, (uint8_t*)OID_PKCS5_DIGEST_ALG},
    CSSMOID_PKCS5_ENCRYPT_ALG = {OID_RSA_ENCRYPT_LENGTH, (uint8_t*)OID_PKCS5_ENCRYPT_ALG},
    CSSMOID_PKCS5_HMAC_SHA1 = {OID_RSA_HASH_LENGTH + 1, (uint8_t*)OID_PKCS5_HMAC_SHA1},
    CSSMOID_PKCS5_pbeWithMD2AndDES = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_pbeWithMD2AndDES},
    CSSMOID_PKCS5_pbeWithMD5AndDES = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_pbeWithMD5AndDES},
    CSSMOID_PKCS5_pbeWithMD2AndRC2 = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_pbeWithMD2AndRC2},
    CSSMOID_PKCS5_pbeWithMD5AndRC2 = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_pbeWithMD5AndRC2},
    CSSMOID_PKCS5_pbeWithSHA1AndDES = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_pbeWithSHA1AndDES},
    CSSMOID_PKCS5_pbeWithSHA1AndRC2 = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_pbeWithSHA1AndRC2},
    CSSMOID_PKCS5_PBKDF2 = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_PBKDF2},
    CSSMOID_PKCS5_PBES2 = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_PBES2},
    CSSMOID_PKCS5_PBMAC1 = {OID_PKCS_5_LENGTH + 1, (uint8_t*)OID_PKCS5_PBMAC1},
    CSSMOID_PKCS5_RC2_CBC = {OID_RSA_ENCRYPT_LENGTH + 1, (uint8_t*)OID_PKCS5_RC2_CBC},
    CSSMOID_PKCS5_DES_EDE3_CBC = {OID_RSA_ENCRYPT_LENGTH + 1, (uint8_t*)OID_PKCS5_DES_EDE3_CBC},
    CSSMOID_PKCS5_RC5_CBC = {OID_RSA_ENCRYPT_LENGTH + 1, (uint8_t*)OID_PKCS5_RC5_CBC};

/* PKCS12 algorithms */
#define OID_PKCS12_PbeIds OID_PKCS_12, 1
#define OID_PKCS12_PbeIds_Length OID_PKCS_12_LENGTH + 1

static const uint8_t OID_PKCS12_pbeWithSHAAnd128BitRC4[] = {OID_PKCS12_PbeIds, 1},
                     OID_PKCS12_pbeWithSHAAnd40BitRC4[] = {OID_PKCS12_PbeIds, 2},
                     OID_PKCS12_pbeWithSHAAnd3Key3DESCBC[] = {OID_PKCS12_PbeIds, 3},
                     OID_PKCS12_pbeWithSHAAnd2Key3DESCBC[] = {OID_PKCS12_PbeIds, 4},
                     OID_PKCS12_pbeWithSHAAnd128BitRC2CBC[] = {OID_PKCS12_PbeIds, 5},
                     OID_PKCS12_pbewithSHAAnd40BitRC2CBC[] = {OID_PKCS12_PbeIds, 6};


const SecAsn1Oid CSSMOID_PKCS12_pbeWithSHAAnd128BitRC4 = {OID_PKCS12_PbeIds_Length + 1,
                                                          (uint8_t*)OID_PKCS12_pbeWithSHAAnd128BitRC4},
                 CSSMOID_PKCS12_pbeWithSHAAnd40BitRC4 = {OID_PKCS12_PbeIds_Length + 1,
                                                         (uint8_t*)OID_PKCS12_pbeWithSHAAnd40BitRC4},
                 CSSMOID_PKCS12_pbeWithSHAAnd3Key3DESCBC = {OID_PKCS12_PbeIds_Length + 1,
                                                            (uint8_t*)OID_PKCS12_pbeWithSHAAnd3Key3DESCBC},
                 CSSMOID_PKCS12_pbeWithSHAAnd2Key3DESCBC = {OID_PKCS12_PbeIds_Length + 1,
                                                            (uint8_t*)OID_PKCS12_pbeWithSHAAnd2Key3DESCBC},
                 CSSMOID_PKCS12_pbeWithSHAAnd128BitRC2CBC = {OID_PKCS12_PbeIds_Length + 1,
                                                             (uint8_t*)OID_PKCS12_pbeWithSHAAnd128BitRC2CBC},
                 CSSMOID_PKCS12_pbewithSHAAnd40BitRC2CBC = {OID_PKCS12_PbeIds_Length + 1,
                                                            (uint8_t*)OID_PKCS12_pbewithSHAAnd40BitRC2CBC};

/* ANSI X9.62 and Certicom elliptic curve algorithms */
static const uint8_t OID_ecPublicKey[] = {OID_ANSI_X9_62_PUBKEY_TYPE, 1},
                     OID_ECDSA_WithSHA1[] = {OID_ANSI_X9_62_SIG_TYPE, 1},
                     OID_ECDSA_WithSHA224[] = {OID_ANSI_X9_62_SIG_TYPE, 3, 1},
                     OID_ECDSA_WithSHA256[] = {OID_ANSI_X9_62_SIG_TYPE, 3, 2},
                     OID_ECDSA_WithSHA384[] = {OID_ANSI_X9_62_SIG_TYPE, 3, 3},
                     OID_ECDSA_WithSHA512[] = {OID_ANSI_X9_62_SIG_TYPE, 3, 4},
                     OID_ECDSA_WithSpecified[] = {OID_ANSI_X9_62_SIG_TYPE, 3};

const SecAsn1Oid CSSMOID_ecPublicKey = {OID_ANSI_X9_62_LEN + 2, (uint8_t*)OID_ecPublicKey},
                 CSSMOID_ECDSA_WithSHA1 = {OID_ANSI_X9_62_SIG_TYPE_LEN + 1, (uint8_t*)OID_ECDSA_WithSHA1},
                 CSSMOID_ECDSA_WithSHA224 = {OID_ANSI_X9_62_SIG_TYPE_LEN + 2,
                                             (uint8_t*)OID_ECDSA_WithSHA224},
                 CSSMOID_ECDSA_WithSHA256 = {OID_ANSI_X9_62_SIG_TYPE_LEN + 2,
                                             (uint8_t*)OID_ECDSA_WithSHA256},
                 CSSMOID_ECDSA_WithSHA384 = {OID_ANSI_X9_62_SIG_TYPE_LEN + 2,
                                             (uint8_t*)OID_ECDSA_WithSHA384},
                 CSSMOID_ECDSA_WithSHA512 = {OID_ANSI_X9_62_SIG_TYPE_LEN + 2,
                                             (uint8_t*)OID_ECDSA_WithSHA512},
                 CSSMOID_ECDSA_WithSpecified = {OID_ANSI_X9_62_SIG_TYPE_LEN + 1,
                                                (uint8_t*)OID_ECDSA_WithSpecified};
