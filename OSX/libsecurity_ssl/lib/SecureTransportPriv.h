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
 * SecureTransportPriv.h - Apple-private exported routines
 */

#ifndef	_SECURE_TRANSPORT_PRIV_H_
#define _SECURE_TRANSPORT_PRIV_H_	1

#include <Security/SecureTransport.h>
#include <Security/SecTrust.h>
#include <Security/sslTypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Enum defining connection strength for TLS connections. */
typedef CF_ENUM(int, SSLConnectionStrength) {
    SSLConnectionStrengthStrong,
    SSLConnectionStrengthWeak,
    SSLConnectionStrengthNonsecure,
};

/* See: https://tools.ietf.org/html/rfc8446#section-4.2.7 */
typedef CF_ENUM(uint16_t, SSLKeyExchangeGroup) {
    SSLKeyExchangeGroupSecp256r1 = 0x0017,
    SSLKeyExchangeGroupSecp384r1 = 0x0018,
    SSLKeyExchangeGroupSecp521r1 = 0x0019,
    SSLKeyExchangeGroupX25519 = 0x001D,
    SSLKeyExchangeGroupX448 = 0x001E,
    SSLKeyExchangeGroupFFDHE2048 = 0x0100,
    SSLKeyExchangeGroupFFDHE3072 = 0x0101,
    SSLKeyExchangeGroupFFDHE4096 = 0x0102,
    SSLKeyExchangeGroupFFDHE6144 = 0x0103,
    SSLKeyExchangeGroupFFDHE8192 = 0x0104,
};

/*
 * Convenience key exchange groups that collate group identifiers of
 * comparable security into a single alias.
 */
typedef CF_ENUM(int, SSLKeyExchangeGroupSet) {
    kSSLKeyExchangeGroupSetDefault,
    kSSLKeyExchangeGroupSetCompatibility,
    kSSLKeyExchangeGroupSetLegacy,
};

/* Determine if a ciphersuite belongs to a specific ciphersuite group */
bool SSLCiphersuiteGroupContainsCiphersuite(SSLCiphersuiteGroup group, SSLCipherSuite suite);

/* Return the list of ciphersuites associated with a SSLCiphersuiteGroup */
const SSLCipherSuite *SSLCiphersuiteGroupToCiphersuiteList(SSLCiphersuiteGroup group,
                                                           size_t *listSize);

/* Determine minimum allowed TLS version for the given ciphersuite */
SSLProtocol SSLCiphersuiteMinimumTLSVersion(SSLCipherSuite ciphersuite);

/* Determine maximum allowed TLS version for the given ciphersuite */
SSLProtocol SSLCiphersuiteMaximumTLSVersion(SSLCipherSuite ciphersuite);

/* Get a human readable name for the given ciphersuite. */
const char *SSLCiphersuiteGetName(SSLCipherSuite ciphersuite);

/* Get the 2-byte IANA codepoint representation of the given TLS protocol version. */
uint16_t SSLProtocolGetVersionCodepoint(SSLProtocol protocol_version);

/* Get the internal SSLProtocol enumeration value from a 2-byte IANA TLS version codepoint. */
SSLProtocol SSLProtocolFromVersionCodepoint(uint16_t protocol_version);

/* Create an SSL Context with an external record layer - eg: kernel accelerated layer */
SSLContextRef
SSLCreateContextWithRecordFuncs(CFAllocatorRef alloc,
                                SSLProtocolSide protocolSide,
                                SSLConnectionType connectionType,
                                const struct SSLRecordFuncs *recFuncs);

/* Set the external record layer context */
OSStatus
SSLSetRecordContext         (SSLContextRef          ctx,
                             SSLRecordContextRef    recCtx);

/* The size of of client- and server-generated random numbers in hello messages. */
#define SSL_CLIENT_SRVR_RAND_SIZE		32

/* The size of the pre-master and master secrets. */
#define SSL_RSA_PREMASTER_SECRET_SIZE	48
#define SSL_MASTER_SECRET_SIZE			48

/*
 * For the following three functions, *size is the available
 * buffer size on entry and the actual size of the data returned
 * on return. The above consts are for convenience.
 */
OSStatus SSLInternalMasterSecret(
   SSLContextRef context,
   void *secret,         // mallocd by caller, SSL_MASTER_SECRET_SIZE
   size_t *secretSize);  // in/out

OSStatus SSLInternalServerRandom(
   SSLContextRef context,
   void *randBuf, 			// mallocd by caller, SSL_CLIENT_SRVR_RAND_SIZE
   size_t *randSize);	// in/out

OSStatus SSLInternalClientRandom(
   SSLContextRef context,
   void *randBuf,  		// mallocd by caller, SSL_CLIENT_SRVR_RAND_SIZE
   size_t *randSize);	// in/out

/*
 * Obtain the sizes of the currently negotiated HMAC digest, session
 * key, and session key IV.
 */
OSStatus SSLGetCipherSizes(
	SSLContextRef context,
	size_t *digestSize,
	size_t *symmetricKeySize,
	size_t *ivSize);

OSStatus SSLInternal_PRF(
   SSLContextRef context,
   const void *secret,
   size_t secretLen,
   const void *label,
   size_t labelLen,
   const void *seed,
   size_t seedLen,
   void *out,   		// mallocd by caller, length >= outLen
   size_t outLen);

/*
 * Obtain a SecTrustRef representing peer certificates. Valid anytime,
 * subsequent to a handshake attempt. The returned SecTrustRef is valid
 * only as long as the SSLContextRef is.
 */
OSStatus
SSLGetPeerSecTrust			(SSLContextRef 		context,
							 SecTrustRef		*secTrust);	/* RETURNED */

/*
 * Obtain resumable session info. Can be called anytime subsequent to
 * handshake attempt.
 *
 * if sessionWasResumed is True on return, the session is indeed a
 * resumed session; the sessionID (an opaque blob generated by the
 * server) is returned in *sessionID. The length of the sessionID
 * is returned in *sessionIDLength. Caller must allocate the
 * sessionID buffer; it max size is MAX_SESSION_ID_LENGTH bytes.
 */
#define MAX_SESSION_ID_LENGTH	32

OSStatus
SSLGetResumableSessionInfo	(
	SSLContextRef	context,
	Boolean			*sessionWasResumed,		// RETURNED
	void			*sessionID,				// RETURNED, mallocd by caller
	size_t			*sessionIDLength);		// IN/OUT

/*
 * Getters for SSLSetCertificate() and SSLSetEncryptionCertificate()
 */
OSStatus
SSLGetCertificate (
	SSLContextRef	context,
	CFArrayRef		*certRefs);				// RETURNED, *not* retained

OSStatus
SSLGetEncryptionCertificate (
	SSLContextRef	context,
	CFArrayRef		*certRefs);				// RETURNED, *not* retained

/*
 * Getter for SSLSetClientSideAuthenticate()
 */
OSStatus
SSLGetClientSideAuthenticate (
	SSLContextRef	context,
	SSLAuthenticate	*auth);					// RETURNED

/*
 * Returns true if an unsafe DH parameter was used when TLS session was
 * negotiated else returns false
 *
 */
bool SSLIsSessionNegotiatedWithUnsafeDH(SSLContextRef context);

#if !TARGET_OS_IPHONE
/*
 * Get/set array of trusted leaf certificates.
 *
 * If none have been set previously with SSLSetTrustedLeafCertificates(),
 * then SSLCopyTrustedLeafCertificates() will return NULL with errSecSuccess.
 */
OSStatus
SSLSetTrustedLeafCertificates (
	SSLContextRef	context,
	CFArrayRef 		certRefs);

OSStatus
SSLCopyTrustedLeafCertificates (
	SSLContextRef	context,
	CFArrayRef 		*certRefs);				// RETURNED, caller must release
#endif
/*
 * Get/set enable of anonymous ciphers. This is deprecated and now a no-op.
 */
OSStatus
SSLSetAllowAnonymousCiphers(
	SSLContextRef	context,
	Boolean			enable);

OSStatus
SSLGetAllowAnonymousCiphers(
	SSLContextRef	context,
	Boolean			*enable);

/*
 * Override the default session cache timeout for a cache entry created for
 * the current session.
 */
OSStatus
SSLSetSessionCacheTimeout(
	SSLContextRef context,
	uint32_t timeoutInSeconds);

/*
 * Callback function for EAP-style PAC-based session resumption.
 * This function is called by SecureTransport to obtain the
 * master secret.
 */
typedef void (*SSLInternalMasterSecretFunction)(
	SSLContextRef ctx,
	const void *arg,		/* opaque to SecureTransport; app-specific */
	void *secret,			/* mallocd by caller, SSL_MASTER_SECRET_SIZE */
	size_t *secretLength);  /* in/out */

/*
 * Register a callback for obtaining the master_secret when performing
 * PAC-based session resumption. At the time the callback is called,
 * the following are guaranteed to be valid:
 *
 *  -- serverRandom (via SSLInternalServerRandom())
 *  -- clientRandom (via SSLInternalClientRandom())
 *  -- negotiated protocol version (via SSLGetNegotiatedProtocolVersion())
 *  -- negotiated CipherSuite (via SSLGetNegotiatedCipher())
 *
 * Currently, PAC-based session resumption is only implemented on
 * the client side for Deployment builds.
 *
 * On the client side, this callback occurs if/when the server sends a
 * ChangeCipherSpec message immediately following its ServerHello
 * message (i.e., it's skipped the entire Key Exchange phase of
 * negotiation).
 *
 * On the server side (Development builds only) this callback occurs
 * immediately upon receipt of the Client Hello message, before we send
 * the Server Hello.
 */
OSStatus
SSLInternalSetMasterSecretFunction(
	SSLContextRef ctx,
	SSLInternalMasterSecretFunction mFunc,
	const void *arg);		/* opaque to SecureTransport; app-specific */

/*
 * Provide an opaque SessionTicket for use in PAC-based session
 * resumption. Client side only. The provided ticket is sent in
 * the ClientHello message as a SessionTicket extension.
 * The maximum ticketLength is 2**16-1.
 */
OSStatus SSLInternalSetSessionTicket(
   SSLContextRef ctx,
   const void *ticket,
   size_t ticketLength);

/*
 * Support for specifying and obtaining ECC curves, used with the ECDH-based
 * ciphersuites.
 */

/*
 * These are the named curves from RFC 4492
 * section 5.1.1, with the exception of SSL_Curve_None which means
 * "ECDSA not negotiated".
 */
typedef enum
{
	SSL_Curve_None = -1,

    SSL_Curve_sect163k1 = 1,
    SSL_Curve_sect163r1 = 2,
    SSL_Curve_sect163r2 = 3,
    SSL_Curve_sect193r1 = 4,
    SSL_Curve_sect193r2 = 5,
    SSL_Curve_sect233k1 = 6,
    SSL_Curve_sect233r1 = 7,
    SSL_Curve_sect239k1 = 8,
    SSL_Curve_sect283k1 = 9,
    SSL_Curve_sect283r1 = 10,
    SSL_Curve_sect409k1 = 11,
    SSL_Curve_sect409r1 = 12,
    SSL_Curve_sect571k1 = 13,
    SSL_Curve_sect571r1 = 14,
    SSL_Curve_secp160k1 = 15,
    SSL_Curve_secp160r1 = 16,
    SSL_Curve_secp160r2 = 17,
    SSL_Curve_secp192k1 = 18,
    SSL_Curve_secp192r1 = 19,
    SSL_Curve_secp224k1 = 20,
    SSL_Curve_secp224r1 = 21,
    SSL_Curve_secp256k1 = 22,

    /* These are the ones we actually support */
	SSL_Curve_secp256r1 = 23,
	SSL_Curve_secp384r1 = 24,
	SSL_Curve_secp521r1 = 25
} SSL_ECDSA_NamedCurve;

/*
 * Obtain the SSL_ECDSA_NamedCurve negotiated during a handshake.
 * Returns errSecParam if no ECDH-related ciphersuite was negotiated.
 */
extern OSStatus SSLGetNegotiatedCurve(
   SSLContextRef ctx,
   SSL_ECDSA_NamedCurve *namedCurve);    /* RETURNED */

/*
 * Obtain the number of currently enabled SSL_ECDSA_NamedCurves.
 */
extern OSStatus SSLGetNumberOfECDSACurves(
   SSLContextRef ctx,
   unsigned *numCurves);				/* RETURNED */

/*
 * Obtain the ordered list of currently enabled SSL_ECDSA_NamedCurves.
 * Caller allocates returned array and specifies its size (in
 * SSL_ECDSA_NamedCurves) in *numCurves on entry; *numCurves
 * is the actual size of the returned array on successful return.
 */
extern OSStatus SSLGetECDSACurves(
   SSLContextRef ctx,
   SSL_ECDSA_NamedCurve *namedCurves,	/* RETURNED */
   unsigned *numCurves);				/* IN/OUT */

/*
 * Specify ordered list of allowable named curves.
 */
extern OSStatus SSLSetECDSACurves(
   SSLContextRef ctx,
   const SSL_ECDSA_NamedCurve *namedCurves,
   unsigned numCurves);

/*
 * Server-specified client authentication mechanisms.
 */
typedef enum {
	/* doesn't appear on the wire */
	SSLClientAuthNone = -1,
	/* RFC 2246 7.4.6 */
	SSLClientAuth_RSASign = 1,
	SSLClientAuth_DSSSign = 2,
	SSLClientAuth_RSAFixedDH = 3,
	SSLClientAuth_DSS_FixedDH = 4,
	/* RFC 4492 5.5 */
	SSLClientAuth_ECDSASign = 64,
	SSLClientAuth_RSAFixedECDH = 65,
	SSLClientAuth_ECDSAFixedECDH = 66
} SSLClientAuthenticationType;

/* TLS 1.2 Signature Algorithms extension values for hash field. */
typedef enum {
    SSL_HashAlgorithmNone = 0,
    SSL_HashAlgorithmMD5 = 1,
    SSL_HashAlgorithmSHA1 = 2,
    SSL_HashAlgorithmSHA224 = 3,
    SSL_HashAlgorithmSHA256 = 4,
    SSL_HashAlgorithmSHA384 = 5,
    SSL_HashAlgorithmSHA512 = 6
} SSL_HashAlgorithm;

/* TLS 1.2 Signature Algorithms extension values for signature field. */
typedef enum {
    SSL_SignatureAlgorithmAnonymous = 0,
    SSL_SignatureAlgorithmRSA = 1,
    SSL_SignatureAlgorithmDSA = 2,
    SSL_SignatureAlgorithmECDSA = 3
} SSL_SignatureAlgorithm;

typedef struct {
    SSL_HashAlgorithm hash;
    SSL_SignatureAlgorithm signature;
} SSLSignatureAndHashAlgorithm;

/*
 * Obtain the number of client authentication mechanisms specified by
 * the server in its Certificate Request message.
 * Returns errSecParam if server hasn't sent a Certificate Request message
 * (i.e., client certificate state is kSSLClientCertNone).
 */
extern OSStatus SSLGetNumberOfClientAuthTypes(
	SSLContextRef ctx,
	unsigned *numTypes);

/*
 * Obtain the client authentication mechanisms specified by
 * the server in its Certificate Request message.
 * Caller allocates returned array and specifies its size (in
 * SSLClientAuthenticationTypes) in *numType on entry; *numTypes
 * is the actual size of the returned array on successful return.
 */
extern OSStatus SSLGetClientAuthTypes(
   SSLContextRef ctx,
   SSLClientAuthenticationType *authTypes,		/* RETURNED */
   unsigned *numTypes);							/* IN/OUT */

/*
 * -- DEPRECATED -- 
 * This is not actually useful. Currently return errSecUnimplemented.
 * The client auth type is fully determined by the type of private key used by
 * the client.
 */
extern OSStatus SSLGetNegotiatedClientAuthType(
   SSLContextRef ctx,
   SSLClientAuthenticationType *authType);		/* RETURNED */


/*
 * Obtain the number of supported_signature_algorithms specified by
 * the server in its Certificate Request message.
 * Returns errSecParam if server hasn't sent a Certificate Request message
 * (i.e., client certificate state is kSSLClientCertNone).
 */
extern OSStatus SSLGetNumberOfSignatureAlgorithms(
    SSLContextRef ctx,
    unsigned *numSigAlgs);

/*
 * Obtain the supported_signature_algorithms specified by
 * the server in its Certificate Request message.
 * Caller allocates returned array and specifies its size (in
 * SSLClientAuthenticationTypes) in *numType on entry; *numTypes
 * is the actual size of the returned array on successful return.
 */
extern OSStatus SSLGetSignatureAlgorithms(
    SSLContextRef ctx,
    SSLSignatureAndHashAlgorithm *sigAlgs,		/* RETURNED */
    unsigned *numSigAlgs);							/* IN/OUT */

/* PSK SPIs */

/* Set the Shared Secret for PSK CipherSuite.
   This need to be set before the handshake starts. */
OSStatus SSLSetPSKSharedSecret(SSLContextRef ctx,
                               const void *secret,
                               size_t secretLen);

/* Set the Client identity for PSK CipherSuite.
   This need to be set before the handshake starts.
   Only useful for client side.*/
OSStatus SSLSetPSKIdentity(SSLContextRef ctx,
                           const void *pskIdentity,
                           size_t pskIdentityLen);

/* For client side, get the identity previously set by SSLSetPSKIdentity.
   For server side, get the identity provided by the client during the handshake.
   Might be NULL if not set. identity is owned by the SSLContext and is invalid once
   the SSLContext is released.
 */
OSStatus SSLGetPSKIdentity(SSLContextRef ctx,
                           const void **pskIdentity,
                           size_t *pskIdentityLen);

/* For client side, set the minimum allowed DH group size for DHE ciphersuites */
OSStatus SSLSetMinimumDHGroupSize(SSLContextRef ctx, unsigned nbits);

OSStatus SSLGetMinimumDHGroupSize(SSLContextRef ctx, unsigned *nbits);

OSStatus SSLSetDHEEnabled(SSLContextRef ctx, bool enabled);

OSStatus SSLGetDHEEnabled(SSLContextRef ctx, bool *enabled);

#if TARGET_OS_IPHONE

/* Following are SPIs on iOS */

/*
 * Set allowed SSL protocol versions. Optional.
 * Specifying kSSLProtocolAll for SSLSetProtocolVersionEnabled results in
 * specified 'enable' boolean to be applied to all supported protocols.
 * The default is "all supported protocols are enabled".
 * This can only be called when no session is active.
 *
 * Legal values for protocol are :
 *		kSSLProtocol2
 *		kSSLProtocol3
 * 		kTLSProtocol1
 *		kSSLProtocolAll
 *
 * This is deprecated in favor of SSLSetProtocolVersionMax/SSLSetProtocolVersionMin
 */
OSStatus
_SSLSetProtocolVersionEnabled (SSLContextRef 	context,
                              SSLProtocol		protocol,
                               Boolean			enable) API_UNAVAILABLE(macCatalyst);

/*
 * Obtain a value specified in SSLSetProtocolVersionEnabled.
 *
 * This is deprecated in favor of SSLGetProtocolVersionMax/SSLGetProtocolVersionMin
 */
OSStatus
_SSLGetProtocolVersionEnabled(SSLContextRef 		context,
                             SSLProtocol		protocol,
                              Boolean			*enable) API_UNAVAILABLE(macCatalyst);		/* RETURNED */

/*
 * Get/set SSL protocol version; optional. Default is kSSLProtocolUnknown,
 * in which case the highest possible version (currently kTLSProtocol1)
 * is attempted, but a lower version is accepted if the peer requires it.
 *
 * SSLSetProtocolVersion can not be called when a session is active.
 *
 * This is deprecated in favor of SSLSetProtocolVersionEnabled.
 *
 * This is deprecated in favor of SSLSetProtocolVersionMax/SSLSetProtocolVersionMin
 */
OSStatus
_SSLSetProtocolVersion		(SSLContextRef 		context,
                             SSLProtocol		version) API_UNAVAILABLE(macCatalyst);

/*
 * Obtain the protocol version specified in SSLSetProtocolVersion.
 * This is deprecated in favor of SSLGetProtocolVersionEnabled.
 * If SSLSetProtocolVersionEnabled() has been called for this session,
 * SSLGetProtocolVersion() may return errSecParam if the protocol enable
 * state can not be represented by the SSLProtocol enums (e.g.,
 * SSL2 and TLS1 enabled, SSL3 disabled).
 *
 * This is deprecated in favor of SSLGetProtocolVersionMax/SSLGetProtocolVersionMin
 */
OSStatus
_SSLGetProtocolVersion		(SSLContextRef		context,
                             SSLProtocol		*protocol) API_UNAVAILABLE(macCatalyst);		/* RETURNED */

/* API REVIEW:
 The following 15 calls were used to change the behaviour of the trust
 evaluation of the certificate chain.
 The proper alternative is to break out of the handshake, get the
 peer's SecTrustRef with SSLCopyPeerTrust and evaluate that.
 */

/*
 * Enable/disable peer certificate chain validation. Default is enabled.
 * If caller disables, it is the caller's responsibility to call
 * SSLCopyPeerTrust() upon successful completion of the handshake
 * and then to perform external validation of the peer certificate
 * chain before proceeding with data transfer.
 */
OSStatus
_SSLSetEnableCertVerify		(SSLContextRef 			context,
                             Boolean				enableVerify) API_UNAVAILABLE(macCatalyst);

OSStatus
_SSLGetEnableCertVerify		(SSLContextRef 			context,
                             Boolean				*enableVerify) API_UNAVAILABLE(macCatalyst);	/* RETURNED */

/*
 * Specify the option of ignoring certificates' "expired" times.
 * This is a common failure in the real SSL world. Default for
 * this flag is false, meaning expired certs result in a
 * errSSLCertExpired error.
 */
OSStatus
_SSLSetAllowsExpiredCerts	(SSLContextRef		context,
                             Boolean			allowsExpired) API_UNAVAILABLE(macCatalyst);

/*
 * Obtain the current value of an SSLContext's "allowExpiredCerts" flag.
 */
OSStatus
_SSLGetAllowsExpiredCerts	(SSLContextRef		context,
                             Boolean			*allowsExpired) API_UNAVAILABLE(macCatalyst); /* RETURNED */

/*
 * Similar to SSLSetAllowsExpiredCerts(), this function allows the
 * option of ignoring "expired" status for root certificates only.
 * Default is false, i.e., expired root certs result in an
 * errSSLCertExpired error.
 */
OSStatus
_SSLSetAllowsExpiredRoots	(SSLContextRef		context,
                             Boolean			allowsExpired) API_UNAVAILABLE(macCatalyst);

OSStatus
_SSLGetAllowsExpiredRoots	(SSLContextRef		context,
                             Boolean			*allowsExpired) API_UNAVAILABLE(macCatalyst); /* RETURNED */

/*
 * Specify option of allowing for an unknown root cert, i.e., one which
 * this software can not verify as one of a list of known good root certs.
 * Default for this flag is false, in which case one of the following two
 * errors may occur:
 *    -- The peer returns a cert chain with a root cert, and the chain
 *       verifies to that root, but the root is not one of our trusted
 *       roots. This results in errSSLUnknownRootCert on handshake.
 *    -- The peer returns a cert chain which does not contain a root cert,
 *       and we can't verify the chain to one of our trusted roots. This
 *       results in errSSLNoRootCert on handshake.
 *
 * Both of these error conditions are ignored when the AllowAnyRoot flag is true,
 * allowing connection to a totally untrusted peer.
 */
OSStatus
_SSLSetAllowsAnyRoot			(SSLContextRef		context,
                                 Boolean			anyRoot) API_UNAVAILABLE(macCatalyst);

/*
 * Obtain the current value of an SSLContext's "allow any root" flag.
 */
OSStatus
_SSLGetAllowsAnyRoot			(SSLContextRef		context,
                                 Boolean			*anyRoot) API_UNAVAILABLE(macCatalyst); /* RETURNED */

/*
 * Augment or replace the system's default trusted root certificate set
 * for this session. If replaceExisting is true, the specified roots will
 * be the only roots which are trusted during this session. If replaceExisting
 * is false, the specified roots will be added to the current set of trusted
 * root certs. If this function has never been called, the current trusted
 * root set is the same as the system's default trusted root set.
 * Successive calls with replaceExisting false result in accumulation
 * of additional root certs.
 *
 * The trustedRoots array contains SecCertificateRefs.
 */
OSStatus
_SSLSetTrustedRoots			(SSLContextRef 		context,
                             CFArrayRef 		trustedRoots,
                             Boolean 			replaceExisting) API_UNAVAILABLE(macCatalyst);

/*
 * Obtain an array of SecCertificateRefs representing the current
 * set of trusted roots. If SSLSetTrustedRoots() has never been called
 * for this session, this returns the system's default root set.
 *
 * Caller must CFRelease the returned CFArray.
 */
OSStatus
_SSLCopyTrustedRoots			(SSLContextRef 		context,
                                 CFArrayRef 		*trustedRoots) API_UNAVAILABLE(macCatalyst);	/* RETURNED */

/*
 * Add a SecCertificateRef, or a CFArray of them, to a server's list
 * of acceptable Certificate Authorities (CAs) to present to the client
 * when client authentication is performed.
 *
 * If replaceExisting is true, the specified certificate(s) will replace
 * a possible existing list of acceptable CAs. If replaceExisting is
 * false, the specified certificate(s) will be appended to the existing
 * list of acceptable CAs, if any.
 *
 * Returns errSecParam is this is called on an SSLContextRef which
 * is configured as a client, or when a session is active.
 */
OSStatus
_SSLSetCertificateAuthorities(SSLContextRef		context,
                             CFTypeRef			certificateOrArray,
                              Boolean 			replaceExisting) API_UNAVAILABLE(macCatalyst);

/*
 * Obtain the certificates specified in SSLSetCertificateAuthorities(),
 * if any. Returns a NULL array if SSLSetCertificateAuthorities() has not
 * been called.
 * Caller must CFRelease the returned array.
 */

OSStatus
_SSLCopyCertificateAuthorities(SSLContextRef		context,
                              CFArrayRef		*certificates) API_UNAVAILABLE(macCatalyst);	/* RETURNED */

/*
 * Request peer certificates. Valid anytime, subsequent to
 * a handshake attempt.
 *
 * The certs argument is a CFArray containing SecCertificateRefs.
 * Caller must CFRelease the returned array.
 *
 * The cert at index 0 of the returned array is the subject (end
 * entity) cert; the root cert (or the closest cert to it) is at
 * the end of the returned array.
 */
/* API REVIEW:
 This should be removed so that applications are not tempted to
 use this to evaluate trust, they should use the SecTrustRef returned
 by SSLCopyPeerTrust instead.
 But this maybe useful to know which certs where returned by the server
 vs which where pulled internally.
 This would be a debug feature, so we deprecate this in iOS. There
 should be an API in SecTrust to allow getting the original certificates
 for debug purpose.
 */
OSStatus
_SSLCopyPeerCertificates		(SSLContextRef 		context,
                             CFArrayRef			*certs) API_UNAVAILABLE(macCatalyst);	/* RETURNED */

/*
 * Specify Diffie-Hellman parameters. Optional; if we are configured to allow
 * for D-H ciphers and a D-H cipher is negotiated, and this function has not
 * been called, a set of process-wide parameters will be calculated. However
 * that can take a long time (30 seconds).
 */
OSStatus _SSLSetDiffieHellmanParams	(SSLContextRef			context,
                                     const void 			*dhParams,
                                     size_t					dhParamsLen) API_UNAVAILABLE(macCatalyst);

/*
 * Return parameter block specified in SSLSetDiffieHellmanParams.
 * Returned data is not copied and belongs to the SSLContextRef.
 */
OSStatus _SSLGetDiffieHellmanParams	(SSLContextRef			context,
                                     const void 			**dhParams,
                                     size_t					*dhParamsLen) API_UNAVAILABLE(macCatalyst);

/*
 * Enable/Disable RSA blinding. This feature thwarts a known timing
 * attack to which RSA keys are vulnerable; enabling it is a tradeoff
 * between performance and security. The default for RSA blinding is
 * enabled.
 */
OSStatus _SSLSetRsaBlinding			(SSLContextRef			context,
                                     Boolean				blinding) API_UNAVAILABLE(macCatalyst);

OSStatus _SSLGetRsaBlinding			(SSLContextRef			context,
                                     Boolean				*blinding) API_UNAVAILABLE(macCatalyst);

/*
 * Create a new SSL/TLS session context.
 * Deprecated: please use the allocator based functions, when available.
 */
OSStatus
_SSLNewContext				(Boolean 			isServer,
                             SSLContextRef 		*tlsContextPtr) API_UNAVAILABLE(macCatalyst);     /* RETURNED */

/*
 * Dispose of an SSLContextRef.  This is effectivly a CFRelease.
 * Deprecated.
 */
OSStatus
_SSLDisposeContext			(SSLContextRef		context) API_UNAVAILABLE(macCatalyst);

/* We redefine the names of all SPIs to avoid collision with unavailable APIs */
#define SSLSetProtocolVersionEnabled _SSLSetProtocolVersionEnabled
#define SSLGetProtocolVersionEnabled _SSLGetProtocolVersionEnabled
#define SSLSetProtocolVersion _SSLSetProtocolVersion
#define SSLGetProtocolVersion _SSLGetProtocolVersion
#define SSLSetEnableCertVerify _SSLSetEnableCertVerify
#define SSLGetEnableCertVerify _SSLGetEnableCertVerify
#define SSLSetAllowsExpiredCerts _SSLSetAllowsExpiredCerts
#define SSLGetAllowsExpiredCerts _SSLGetAllowsExpiredCerts
#define SSLSetAllowsExpiredRoots _SSLSetAllowsExpiredRoots
#define SSLGetAllowsExpiredRoots _SSLGetAllowsExpiredRoots
#define SSLSetAllowsAnyRoot _SSLSetAllowsAnyRoot
#define SSLGetAllowsAnyRoot _SSLGetAllowsAnyRoot
#define SSLSetTrustedRoots _SSLSetTrustedRoots
#define SSLCopyTrustedRoots _SSLCopyTrustedRoots
#define SSLSetCertificateAuthorities _SSLSetCertificateAuthorities
#define SSLCopyCertificateAuthorities _SSLCopyCertificateAuthorities
#define SSLCopyPeerCertificates _SSLCopyPeerCertificates
#define SSLSetDiffieHellmanParams _SSLSetDiffieHellmanParams
#define SSLGetDiffieHellmanParams _SSLGetDiffieHellmanParams
#define SSLSetRsaBlinding   _SSLSetRsaBlinding
#define SSLGetRsaBlinding	_SSLGetRsaBlinding
#define SSLNewContext _SSLNewContext
#define SSLNewDatagramContext _SSLNewDatagramContext
#define SSLDisposeContext _SSLDisposeContext

#endif /* TARGET_OS_IPHONE */

/*
 * Map the SSLProtocol enum to an enum capturing the wire format (coreTLS) version.
 */
#define SECURITY_HAS_TLS_VERSION_TRANSLATOR 1
tls_protocol_version
_SSLProtocolVersionToWireFormatValue   (SSLProtocol protocol);


/*
 * Create a new Datagram TLS session context.
 * Use in place of SSLNewContext to create a DTLS session.
 * Deprecated: please use the allocator based functions, when available.
 * Also note: the symbol is prefixed with underscore in iOS (historical)
 */
OSStatus
SSLNewDatagramContext		(Boolean 			isServer,
                             SSLContextRef 		*dtlsContextPtr) API_UNAVAILABLE(macCatalyst);	/* RETURNED */



/*
 * NPN support.
 *
 * If used, must be by client and server before SSLHandshake()
 *
 * Client: if set the client will announce NPN extension in the
 * ClientHello, and the a callback will provide the server list, at
 * that time the client needs to call SSLSetNPNData() in the callback
 * to provide to the server the support mechanism.
 *
 * Server: the callback will tell the server that the client supports
 * NPN and at that time, the server needs to set the supported NPN
 * types with SSLSetNPNData().
 */
typedef void
(*SSLNPNFunc)               (SSLContextRef          ctx,
                             void                   *info,		/* info pointer provided by SSLSetNPNFunc */
                             const void			    *npnData,
                             size_t                 npnDataLength);


void
SSLSetNPNFunc               (SSLContextRef      context,
                             SSLNPNFunc         npnFunc,
                             void               *info)
    __OSX_AVAILABLE_STARTING(__MAC_10_10, __IPHONE_8_0);

/*
 * For servers, this is the data that is announced.
 * For clients, this is the picked data in the npnFunc callback.
 *
 * Return an error on out of memory and if buffer it too large
 */
OSStatus
SSLSetNPNData				(SSLContextRef      context,
                             const void *data,
							 size_t length)
    __OSX_AVAILABLE_STARTING(__MAC_10_10, __IPHONE_8_0);

/*
 * For servers, return client provided npn data if sent
 */
const void *
SSLGetNPNData				(SSLContextRef      context,
							 size_t				*length)
    __OSX_AVAILABLE_STARTING(__MAC_10_10, __IPHONE_8_0);

// ALPN
typedef void
(*SSLALPNFunc)             (SSLContextRef          ctx,
                            void                    *info,		/* info pointer provided by SSLSetALPNFunc */
                            const void			    *alpnData,
                            size_t                  alpnDataLength);

void
SSLSetALPNFunc              (SSLContextRef      context,
                             SSLALPNFunc         alpnFunc,
                             void               *info)
    __OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0);


OSStatus
SSLSetALPNData				(SSLContextRef      context,
                             const void *data,
                             size_t length)
    __OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0);

const void *
SSLGetALPNData				(SSLContextRef      context,
                             size_t				*length)
    __OSX_AVAILABLE_STARTING(__MAC_10_11, __IPHONE_9_0);

// end of ALPN

#ifdef __cplusplus
}
#endif


#endif	/* _SECURE_TRANSPORT_PRIV_H_ */
