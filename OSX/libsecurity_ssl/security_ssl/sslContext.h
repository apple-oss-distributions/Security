/*
 * Copyright (c) 1999-2001,2005-2014 Apple Inc. All Rights Reserved.
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
 * sslContext.h - Private SSL typedefs: SSLContext and its components
 */

#ifndef _SSLCONTEXT_H_
#define _SSLCONTEXT_H_ 1

#include "SecureTransport.h"
#include "sslBuildFlags.h"

#include <tls_handshake.h>
#include <tls_record.h>
#include <tls_stream_parser.h>
#include <tls_cache.h>

#ifdef USE_CDSA_CRYPTO
#include <Security/cssmtype.h>
#else
#if TARGET_OS_IPHONE
#include <Security/SecDH.h>
#include <Security/SecKeyInternal.h>
#else
#include "../sec/Security/SecDH.h"  // hack to get SecDH.
// typedef struct OpaqueSecDHContext *SecDHContext;
#endif
#include <corecrypto/ccec.h>
#endif

#include <CoreFoundation/CFRuntime.h>
#include <AssertMacros.h>

#include "sslPriv.h"
#include "sslRecord.h"
#include "cipherSpecs.h"

#include <dispatch/dispatch.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{   SSLReadFunc         read;
    SSLWriteFunc        write;
    SSLConnectionRef   	ioRef;
} IOContext;

//FIXME should not need this.
typedef enum
{
    SSL_HdskStateUninit = 0,			/* No Handshake yet */
    SSL_HdskStatePending,               /* Handshake in Progress */
    SSL_HdskStateReady,                 /* Handshake is done */
    SSL_HdskStateGracefulClose,
    SSL_HdskStateErrorClose,
    SSL_HdskStateNoNotifyClose,			/* Server disconnected with no notify msg */
    SSL_HdskStateOutOfBandError,        /* The caller encountered an error with out-of-band message processing */
} SSLHandshakeState;

#define SSLChangeHdskState(ctx, newState) { ctx->state=newState; }

struct SSLContext
{
	CFRuntimeBase		_base;
    IOContext           ioCtx;

    const struct SSLRecordFuncs *recFuncs;
    SSLRecordContextRef recCtx;

    tls_handshake_t hdsk;
    tls_cache_t cache;
    int readCipher_ready;
    int writeCipher_ready;

    SSLHandshakeState   state;
    OSStatus outOfBandError;

	/* 
	 * Prior to successful protocol negotiation, negProtocolVersion
	 * is SSL_Version_Undetermined. Subsequent to successful
	 * negotiation, negProtocolVersion contains the actual over-the-wire
	 * protocol value.
	 *
	 * The Boolean versionEnable flags are set by
	 * SSLSetProtocolVersionEnabled or SSLSetProtocolVersion and
	 * remain invariant once negotiation has started. If there
	 * were a large number of these and/or we were adding new
	 * protocol versions on a regular basis, we'd probably want
	 * to implement these as a word of flags. For now, in the
	 * real world, this is the most straightforward implementation.
	 */
    tls_protocol_version  negProtocolVersion;	/* negotiated */
    tls_protocol_version  clientReqProtocol;	/* requested by client in hello msg */
    tls_protocol_version  minProtocolVersion;
    tls_protocol_version  maxProtocolVersion;
    Boolean             isDTLS;             /* if this is a Datagram Context */
    SSLProtocolSide     protocolSide;		/* ConnectionEnd enum { server, client } in rfc5246. */

    SSLBuffer           dtlsCookie;         /* DTLS ClientHello cookie */


    uint16_t            selectedCipher;		/* currently selected */

    /* Server DH Parameters */
    SSLBuffer			dhParamsEncoded;	/* PKCS3 encoded blob - prime + generator */

	/*
	 * The arrays we are given via SSLSetCertificate() and SSLSetEncryptionCertificate().
	 * We keep them here, refcounted, solely for the associated getter.
	 */
    CFArrayRef			localCertArray;
    CFArrayRef			encryptCertArray;

	/* peer certs as SecTrustRef */
	SecTrustRef			peerSecTrust;

    CFMutableArrayRef   trustedCerts;
    Boolean             trustedCertsOnly;

#if !TARGET_OS_IPHONE
    /*
     * trusted leaf certs as specified in SSLSetTrustedLeafCertificates()
     */
    CFArrayRef			trustedLeafCerts;
#endif

	Boolean					allowExpiredCerts;
	Boolean					allowExpiredRoots;
	Boolean					enableCertVerify;

    SSLBuffer		    sessionID;
    SSLBuffer			peerID;
    SSLBuffer			resumableSession;       /* We keep a copy for now - but eventually this should go away if we get refcounted SSLBuffers */

    uint16_t            *ecdhCurves;
    unsigned            ecdhNumCurves;

	/* server-side only */
    SSLAuthenticate		clientAuth;				/* kNeverAuthenticate, etc. */

	/* client and server */
	SSLClientCertificateState	clientCertState;

    DNListElem          *acceptableDNList;		/* client and server */
	CFMutableArrayRef	acceptableCAs;			/* server only - SecCertificateRefs */

    bool                certRequested;
    bool                certSent;
    bool                certReceived;
    bool                x509Requested;

    unsigned            sessionMatch;


	/* Transport layer fields */
    SSLBuffer			receivedDataBuffer;
    size_t              receivedDataPos;

	Boolean				allowAnyRoot;		// don't require known roots
	Boolean				sentFatalAlert;		// this session terminated by fatal alert
	Boolean				rsaBlindingEnable;
	Boolean				oneByteRecordEnable;    /* enable 1/n-1 data splitting for TLSv1 and SSLv3 */

	/* optional session cache timeout (in seconds) override - 0 means default */
	uint32_t 			sessionCacheTimeout;

	/* optional SessionTicket */
	SSLBuffer			sessionTicket;

	/* optional callback to obtain master secret, with its opaque arg */
	SSLInternalMasterSecretFunction	masterSecretCallback;
	const void 			*masterSecretArg;

	#if 	SSL_PAC_SERVER_ENABLE
	/* server PAC resume sets serverRandom early to allow for secret acquisition */
	uint8_t				serverRandomValid;
	#endif

	Boolean				anonCipherEnable;

	/* optional switches to enable additional returns from SSLHandshake */
    Boolean             breakOnServerAuth;
    Boolean             breakOnCertRequest;
    Boolean             breakOnClientAuth;
    Boolean             signalServerAuth;
    Boolean             signalCertRequest;
    Boolean             signalClientAuth;
    Boolean             breakOnClientHello;
    Boolean             allowServerIdentityChange;
    Boolean             allowRenegotiation;
    Boolean             enableSessionTickets;

    /* cached configuration buffer */
    SSLBuffer           contextConfigurationBuffer;

    /* List of peer-specified supported_signature_algorithms */
	unsigned					 numPeerSigAlgs;
	const tls_signature_and_hash_algorithm *peerSigAlgs;

	/* List of server-specified client auth types */
	unsigned					numAuthTypes;
	const tls_client_auth_type *clientAuthTypes;

    /* Timeout for DTLS retransmit */
    CFAbsoluteTime      timeout_deadline;
    CFAbsoluteTime      timeout_duration;
    size_t              mtu;

    /* RFC 5746: Secure renegotiation */
    Boolean             secure_renegotiation;
    Boolean             secure_renegotiation_received;
    SSLBuffer           ownVerifyData;
    SSLBuffer           peerVerifyData;

    /* RFC 4279: TLS PSK */
    SSLBuffer           pskSharedSecret;
    SSLBuffer           pskIdentity;

    /* TLS False Start */
    Boolean             falseStartEnabled; //FalseStart enabled (by API call)
    /* Fallback behavior */
    Boolean             fallbackEnabled; // Fallback behavior enabled.
    /* NPN */
    SSLNPNFunc      npnFunc;
    void            *npnFuncInfo;

    /* ALPN */
    SSLALPNFunc     alpnFunc;
    void            *alpnFuncInfo;

    /* Enable DHE or not */
    bool            dheEnabled;

    /* For early failure reporting */
    bool    serverHelloReceived;
};

OSStatus SSLUpdateNegotiatedClientAuthType(SSLContextRef ctx);

Boolean sslIsSessionActive(const SSLContext *ctx);

OSStatus SSLGetSessionConfigurationIdentifier(SSLContext *ctx, SSLBuffer *buffer);

/* This is implemented in tls_callbacks.c */
int sslGetSessionID(SSLContext *myCtx, SSLBuffer *sessionID);

#ifdef __cplusplus
}
#endif

#endif /* _SSLCONTEXT_H_ */
