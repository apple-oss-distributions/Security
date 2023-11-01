/*
 * Copyright (c) 2005,2011-2016 Apple Inc. All Rights Reserved.
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
 * SecTrustSettings.cpp - Public interface for manipulation of Trust Settings.
 *
 */

#include "SecBridge.h"
#include <Security/SecCertificatePriv.h>
#include <Security/SecTrustSettings.h>
#include <Security/SecTrustSettingsPriv.h>
#include "SecTrustSettingsCertificates.h"
#include "SecCFRelease.h"
#include "TrustSettingsUtils.h"
#include "TrustSettings.h"
#include "TrustSettingsSchema.h"
#include "TrustKeychains.h"
#include "Trust.h"
#include "SecKeychainPriv.h"
#include "Globals.h"
#include <security_utilities/threading.h>
#include <security_utilities/globalizer.h>
#include <security_utilities/errors.h>
#include <security_cdsa_utilities/cssmerrors.h>
#include <security_utilities/logging.h>
#include <security_utilities/debugging.h>
#include <security_utilities/simpleprefs.h>
#include <securityd_client/dictionary.h>
#include <securityd_client/ssclient.h>
#include <security_utilities/simulatecrash_assert.h>
#include <dlfcn.h>
#include <libproc.h>
#include <syslog.h>
#include <vector>
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CFPreferences.h>
#include <utilities/SecCFRelease.h>
#include <utilities/SecDispatchRelease.h>

#define trustSettingsDbg(args...)	secinfo("trustSettings", ## args)

/*
 * Ideally we'd like to implement our own lock to protect the state of the cert stores
 * without grabbing the global Sec API lock, but we deal with SecCFObjects, so we'll have
 * to bite the bullet and grab the big lock. We also have our own lock protecting the
 * global trust settings cache which is also used by the keychain callback function
 * (which does not grab the Sec API lock).
 */

#define BEGIN_RCSAPI	\
	OSStatus __secapiresult; \
	try {
#define END_RCSAPI		\
		__secapiresult=errSecSuccess; \
	} \
	catch (const MacOSError &err) { __secapiresult=err.osStatus(); } \
	catch (const CommonError &err) { __secapiresult=SecKeychainErrFromOSStatus(err.osStatus()); } \
	catch (const std::bad_alloc &) { __secapiresult=errSecAllocate; } \
	catch (...) { __secapiresult=errSecInternalComponent; } \
	return __secapiresult;

#define END_RCSAPI0		\
	catch (...) {} \
	return;


#pragma mark --- TrustSettings preferences ---

/*
 * If Colonel Klink wants to disable user-level Trust Settings, he'll have
 * to restart the apps which will be affected after he does so. We are not
 * going to consult system prefs every time we do a cert evaluation. We
 * consult it once per process and cache the results here.
 */
static bool tsUserTrustDisableValid = false;	/* true once we consult prefs */
static bool tsUserTrustDisable = false;			/* the cached value */

/*
 * Determine whether user-level Trust Settings disabled.
 */
static bool tsUserTrustSettingsDisabled()
{
	if(tsUserTrustDisableValid) {
		return tsUserTrustDisable;
	}
	tsUserTrustDisable = false;

	Dictionary* dictionary = Dictionary::CreateDictionary(kSecTrustSettingsPrefsDomain, Dictionary::US_System);
	if (dictionary)
	{
		unique_ptr<Dictionary> prefsDict(dictionary);
		/* this returns false if the pref isn't there, just like we want */
		tsUserTrustDisable = prefsDict->getBoolValue(kSecTrustSettingsDisableUserTrustSettings);
	}

	tsUserTrustDisableValid = true;
	return tsUserTrustDisable;
}

#pragma mark --- TrustSettings global cache ---

/***
 *** cache submodule - keeps per-app copy of zero or one TrustSettings
 ***  				   for each domain. Used only by SecTrustSettingsEvaluateCert()
 ***				   and SecTrustSettingsCopyQualifiedCerts(); results of
 ***				   manipulation by public API functions are not cached.
 ***/

/*
 * API/client code has to hold this lock when doing anything with any of
 * the TrustSettings maintained here.
 * It's recursive to accomodate CodeSigning's need to do cert verification
 * (while we evaluate app equivalence).
 */
static ModuleNexus<RecursiveMutex> sutCacheLock;

#define TRUST_SETTINGS_NUM_DOMAINS		3

/*
 * The three global TrustSettings.
 * We rely on the fact the the domain enums start with 0; we use
 * the domain value as an index into the following two arrays.
 */
static TrustSettings *globalTrustSettings[TRUST_SETTINGS_NUM_DOMAINS] =
		{NULL, NULL, NULL};

/*
 * Indicates "the associated global here is currently valid; if there isn't a
 * globalTrustSettings[domain], don't try to find one"
 */
static bool globalTrustSettingsValid[TRUST_SETTINGS_NUM_DOMAINS] =
		{false, false, false};

/* remember the fact that we've registered our KC callback */
static bool sutRegisteredCallback = false;

static void tsRegisterCallback();

/*
 * Assign global TrustSetting to new incoming value, which may be NULL.
 * Caller holds sutCacheLock.
 */
static void tsSetGlobalTrustSettings(
	TrustSettings *ts,
	SecTrustSettingsDomain domain)
{
	assert(((int)domain >= 0) && ((int)domain < TRUST_SETTINGS_NUM_DOMAINS));

	trustSettingsDbg("tsSetGlobalTrustSettings domain %d: caching TS %p old TS %p",
		(int)domain, ts, globalTrustSettings[domain]);
	delete globalTrustSettings[domain];
	globalTrustSettings[domain] = ts;
	globalTrustSettingsValid[domain] = ts ? true : false;
	tsRegisterCallback();
}

/*
 * Obtain global TrustSettings for specified domain if it exists.
 * Returns NULL if there is simply no TS for that domain.
 * The TS, if returned, belongs to this cache module.
 * Caller holds sutCacheLock.
 */
static TrustSettings *tsGetGlobalTrustSettings(
	SecTrustSettingsDomain domain)
{
	assert(((int)domain >= 0) && ((int)domain < TRUST_SETTINGS_NUM_DOMAINS));

	if((domain == kSecTrustSettingsDomainUser) && tsUserTrustSettingsDisabled()) {
		trustSettingsDbg("tsGetGlobalTrustSettings: skipping DISABLED user domain");
		return NULL;
	}

	if(globalTrustSettingsValid[domain]) {
		// ready or not, use this
		return globalTrustSettings[domain];
	}
	assert(globalTrustSettings[domain] == NULL);

	/* try to find one */
	OSStatus result = errSecSuccess;
	TrustSettings *ts = NULL;
	/* don't create; trim if found */
	result = TrustSettings::CreateTrustSettings(domain, CREATE_NO, TRIM_YES, ts);
    if (   (domain != kSecTrustSettingsDomainSystem)
        && (result == errSecInternalComponent)) {
        /*
         * Could not connect to ocspd to get the user/admin domain trust settings
         * This happens in single user mode for example.
         * Valid flag is set to false and continue.
         */
        trustSettingsDbg("tsGetGlobalTrustSettings: could not connect to ocspd for domain (%d)",(int)domain);
        globalTrustSettingsValid[domain] = false;
        tsRegisterCallback();
        return NULL;
    }
    else if (result == errSecNoTrustSettings) {
		/*
		 * No TrustSettings for this domain, actually a fairly common case.
		 * Optimize: don't bother trying this again.
		 */
		trustSettingsDbg("tsGetGlobalTrustSettings: flagging known NULL");
		globalTrustSettingsValid[domain] = true;
		tsRegisterCallback();
		return NULL;
	}
    else if(result != errSecSuccess) {
        /* gross error */
        MacOSError::throwMe(result);
    }

	tsSetGlobalTrustSettings(ts, domain);
	return ts;
}

/*
 * Purge TrustSettings cache.
 * Called by Keychain Event callback and by our API functions that
 * modify trust settings.
 * Caller can NOT hold sutCacheLock.
 */
static void tsPurgeCache()
{
	int domain;

	StLock<Mutex>	_(sutCacheLock());
	trustSettingsDbg("tsPurgeCache");
	for(domain=0; domain<TRUST_SETTINGS_NUM_DOMAINS; domain++) {
		tsSetGlobalTrustSettings(NULL, (SecTrustSettingsDomain) domain);
	}
}

/*
 * Keychain event callback function, for notification by other processes that
 * user trust list(s) has/have changed.
 */
static OSStatus tsTrustSettingsCallback (
   SecKeychainEvent keychainEvent,
   SecKeychainCallbackInfo *info,
   void *context)
{
	trustSettingsDbg("tsTrustSettingsCallback, event %d", (int)keychainEvent);
	if(keychainEvent != kSecTrustSettingsChangedEvent) {
		/* should not happen, right? */
		return errSecSuccess;
	}
	if(info->pid == getpid()) {
		/*
		 * Avoid dup cache invalidates: we already dealt with this event.
		 */
		trustSettingsDbg("cacheEventCallback: our pid, skipping");
	}
	else {
		tsPurgeCache();
	}
	return errSecSuccess;
}

/*
 * Ensure that we've registered for kSecTrustSettingsChangedEvent callbacks
 */
static void tsRegisterCallback()
{
	if(sutRegisteredCallback) {
		return;
	}
	trustSettingsDbg("tsRegisterCallback: registering callback");
	OSStatus ortn = SecKeychainAddCallback(tsTrustSettingsCallback,
		kSecTrustSettingsChangedEventMask, NULL);
	if(ortn) {
		trustSettingsDbg("tsRegisterCallback: SecKeychainAddCallback returned %d", (int)ortn);
		/* Not sure how this could ever happen - maybe if there is no run loop active? */
	}
	sutRegisteredCallback = true;
}

#pragma mark --- Static functions ---


/*
 * Called by API code when a trust list has changed; we notify other processes
 * and purge our own cache.
 */
static void tsTrustSettingsChanged()
{
	tsPurgeCache();
    SecTrustSettingsPurgeUserAdminCertsCache();

	/* The only interesting data is our pid */
	NameValueDictionary nvd;
	pid_t ourPid = getpid();
	nvd.Insert (new NameValuePair (PID_KEY,
		CssmData (reinterpret_cast<void*>(&ourPid), sizeof (pid_t))));
	CssmData data;
	nvd.Export (data);

	trustSettingsDbg("tsTrustSettingsChanged: posting notification");
	SecurityServer::ClientSession cs (Allocator::standard(), Allocator::standard());
	cs.postNotification (SecurityServer::kNotificationDomainDatabase,
		kSecTrustSettingsChangedEvent, data);
	free (data.data ());
}

/*
 * Common code for SecTrustSettingsCopyTrustSettings(),
 * SecTrustSettingsCopyModificationDate().
 */
static OSStatus tsCopyTrustSettings(
	SecCertificateRef cert,
	SecTrustSettingsDomain domain,
	CFArrayRef *trustSettings,		/* optionally RETURNED */
	CFDateRef *modDate)				/* optionally RETURNED */
{
	BEGIN_RCSAPI

	TS_REQUIRED(cert)

	/* obtain fresh full copy from disk */
	OSStatus result;
	TrustSettings* ts;

	result = TrustSettings::CreateTrustSettings(domain, CREATE_NO, TRIM_NO, ts);

	// rather than throw these results, just return them because we are at the top level
	if (result == errSecNoTrustSettings) {
		return errSecItemNotFound;
	}
	else if (result != errSecSuccess) {
		return result;
	}

	unique_ptr<TrustSettings>_(ts); // make sure this gets deleted just in case something throws underneath

	if(trustSettings) {
		*trustSettings = ts->copyTrustSettings(cert);
	}
	if(modDate) {
		*modDate = ts->copyModDate(cert);
	}

	END_RCSAPI
}

/*
 * Common code for SecTrustSettingsCopyTrustSettings(),
 * SecTrustSettingsCopyModificationDate().
 */
static OSStatus tsCopyTrustSettings_cached(
    SecCertificateRef cert,
    SecTrustSettingsDomain domain,
    CFArrayRef CF_RETURNS_RETAINED *trustSettings)
{
    BEGIN_RCSAPI

    TS_REQUIRED(cert)

    StLock<Mutex>    _(sutCacheLock());
    TrustSettings* ts = tsGetGlobalTrustSettings(domain);

    // rather than throw these results, just return them because we are at the top level
    if (ts == NULL) {
        return errSecItemNotFound;
    }

    if(trustSettings) {
        *trustSettings = ts->copyTrustSettings(cert);
    }

    END_RCSAPI
}

static OSStatus tsContains(
    SecCertificateRef cert,
    SecTrustSettingsDomain domain)
{
    BEGIN_RCSAPI

    TS_REQUIRED(cert)

    StLock<Mutex>    _(sutCacheLock());
    TrustSettings* ts = tsGetGlobalTrustSettings(domain);

    // rather than throw these results, just return them because we are at the top level
    if (ts == NULL) {
        return errSecItemNotFound;
    }

    if (ts->contains(cert)) {
        return errSecSuccess;
    } else {
        return errSecItemNotFound;
    }

    END_RCSAPI
}

static void tsAddConditionalCerts(CFMutableArrayRef certArray);

/*
 * Common code for SecTrustSettingsCopyQualifiedCerts() and
 * SecTrustSettingsCopyUnrestrictedRoots().
 */
static OSStatus tsCopyCertsCommon(
	/* usage constraints, all optional */
	const CSSM_OID			*policyOID,
	const char				*policyString,
	SecTrustSettingsKeyUsage keyUsage,
	/* constrain to only roots */
	bool					onlyRoots,
	/* per-domain enables */
	bool					user,
	bool					admin,
	bool					system,
	CFArrayRef				*certArray)		/* RETURNED */
{
	StLock<Mutex> _TC(sutCacheLock());
	StLock<Mutex> _TK(SecTrustKeychainsGetMutex());

	TS_REQUIRED(certArray)

	/* this relies on the domain enums being numbered 0..2, user..system */
	bool domainEnable[3] = {user, admin, system};

	/* we'll retain it again before successful exit */
	CFRef<CFMutableArrayRef> outArray(CFArrayCreateMutable(NULL, 0,
		&kCFTypeArrayCallBacks));

	/*
	 * Search all keychains - user's keychain list, System.keychain,
	 * and system root store
	 */
	StorageManager::KeychainList keychains;
	Keychain adminKc;
	if(user) {
		globals().storageManager.getSearchList(keychains);
	}
	if(user || admin) {
		adminKc = globals().storageManager.make(ADMIN_CERT_STORE_PATH, false);
		keychains.push_back(adminKc);
	}
	Keychain sysRootKc = globals().storageManager.make(SYSTEM_ROOT_STORE_PATH, false);
	keychains.push_back(sysRootKc);

	assert(kSecTrustSettingsDomainUser == 0);
	for(unsigned domain=0; domain<TRUST_SETTINGS_NUM_DOMAINS; domain++) {
		if(!domainEnable[domain]) {
			continue;
		}
		TrustSettings *ts = tsGetGlobalTrustSettings((SecTrustSettingsDomain)domain);
		if(ts == NULL) {
			continue;
		}
		ts->findQualifiedCerts(keychains,
			false, 		/* !findAll */
			onlyRoots,
			policyOID, policyString, keyUsage,
			outArray);
	}
	if (system) {
		tsAddConditionalCerts(outArray);
	}
	*certArray = outArray;
	CFRetainSafe(*certArray);
	trustSettingsDbg("tsCopyCertsCommon: %ld certs found",
		CFArrayGetCount(outArray));
	return errSecSuccess;
}

static void tsAddConditionalCerts(CFMutableArrayRef certArray)
{
#if TARGET_OS_OSX
	struct certmap_entry_s {
		CFStringRef bundleId;
		const UInt8* data;
		const CFIndex length;
	};
	typedef struct certmap_entry_s certmap_entry_t;

	CFBundleRef bundle = CFBundleGetMainBundle();
	CFStringRef bundleIdentifier = (bundle) ? CFBundleGetIdentifier(bundle) : NULL;
	if (!bundleIdentifier || !certArray) { return; }

	// conditionally include 1024-bit compatibility roots for specific apps
	const certmap_entry_t certmap[] = {
		{ CFSTR("com.autodesk.AdSSO"), _GTECyberTrustGlobalRootCA, sizeof(_GTECyberTrustGlobalRootCA) }, // rdar://25916338
		{ CFSTR("com.clo3d.MD5"), _ThawtePremiumServerCA, sizeof(_ThawtePremiumServerCA) }, // rdar://26281864
	};

	unsigned int i, certmaplen = sizeof(certmap) / sizeof(certmap_entry_t);
	for (i=0; i<certmaplen; i++) {
		if (CFStringCompare(bundleIdentifier, certmap[i].bundleId, 0) == kCFCompareEqualTo) {
			SecCertificateRef cert = SecCertificateCreateWithBytes(NULL, certmap[i].data, certmap[i].length);
			if (!cert) { continue; }
			CFArrayAppendValue(certArray, cert);
			CFRelease(cert);
			cert = NULL;
		}
	}
#else
	// this function is a no-op on iOS platforms
#endif
}


#pragma mark --- SPI functions ---


/*
 * Fundamental routine used by TP to ascertain status of one cert.
 *
 * Returns true in *foundMatchingEntry if a trust setting matching
 * specific constraints was found for the cert. Returns true in
 * *foundAnyEntry if any entry was found for the cert, even if it
 * did not match the specified constraints. The TP uses this to
 * optimize for the case where a cert is being evaluated for
 * one type of usage, and then later for another type. If
 * foundAnyEntry is false, the second evaluation need not occur.
 *
 * Returns the domain in which a setting was found in *foundDomain.
 *
 * Allowed errors applying to the specified cert evaluation
 * are returned in a mallocd array in *allowedErrors and must
 * be freed by caller.
 *
 * The design of the entire TrustSettings module is centered around
 * optimizing the performance of this routine (security concerns
 * aside, that is). It's why the per-cert dictionaries are stored
 * as a dictionary, keyed off of the cert hash. It's why TrustSettings
 * are cached in memory by tsGetGlobalTrustSettings(), and why those
 * cached TrustSettings objects are 'trimmed' of dictionary fields
 * which are not needed to verify a cert.
 *
 * The API functions which are used to manipulate Trust Settings
 * are called infrequently and need not be particularly fast since
 * they result in user interaction for authentication. Thus they do
 * not use cached TrustSettings as this function does.
 */
OSStatus SecTrustSettingsEvaluateCert(
	CFStringRef				certHashStr,
	/* parameters describing the current cert evalaution */
	const CSSM_OID			*policyOID,
	const char				*policyString,		/* optional */
	uint32					policyStringLen,
	SecTrustSettingsKeyUsage keyUsage,			/* optional */
	bool					isRootCert,			/* for checking default setting */
	/* RETURNED values */
	SecTrustSettingsDomain	*foundDomain,
	CSSM_RETURN				**allowedErrors,	/* mallocd */
	uint32					*numAllowedErrors,
	SecTrustSettingsResult	*resultType,
	bool					*foundMatchingEntry,
	bool					*foundAnyEntry)
{
	BEGIN_RCSAPI

	StLock<Mutex>	_(sutCacheLock());

	TS_REQUIRED(certHashStr)
	TS_REQUIRED(foundDomain)
	TS_REQUIRED(allowedErrors)
	TS_REQUIRED(numAllowedErrors)
	TS_REQUIRED(resultType)
	TS_REQUIRED(foundMatchingEntry)
	TS_REQUIRED(foundAnyEntry)

	/* ensure a NULL_terminated string */
	auto_array<char> polStr;
	if(policyString != NULL && policyStringLen > 0) {
		polStr.allocate(policyStringLen + 1);
		memmove(polStr.get(), policyString, policyStringLen);
		if(policyString[policyStringLen - 1] != '\0') {
			(polStr.get())[policyStringLen] = '\0';
		}
	}

	/* initial condition - this can grow if we inspect multiple TrustSettings */
	*allowedErrors = NULL;
	*numAllowedErrors = 0;

	/*
	 * This loop relies on the ordering of the SecTrustSettingsDomain enum:
	 * search user first, then admin, then system.
	 */
	assert(kSecTrustSettingsDomainAdmin == (kSecTrustSettingsDomainUser + 1));
	assert(kSecTrustSettingsDomainSystem == (kSecTrustSettingsDomainAdmin + 1));
	bool foundAny = false;
	for(unsigned domain=kSecTrustSettingsDomainUser;
			     domain<=kSecTrustSettingsDomainSystem;
				 domain++) {
		TrustSettings *ts = tsGetGlobalTrustSettings((SecTrustSettingsDomain)domain);
		if(ts == NULL) {
			continue;
		}

		/* validate cert returns true if matching entry was found */
		bool foundAnyHere = false;
		bool found = ts->evaluateCert(certHashStr, policyOID,
			polStr.get(), keyUsage, isRootCert,
			allowedErrors, numAllowedErrors, resultType, &foundAnyHere);

		if(found) {
			/*
			 * Note this, even though we may overwrite it later if this
			 * is an Unspecified entry and we find a definitive entry
			 * later
			 */
			*foundDomain = (SecTrustSettingsDomain)domain;
		}
		if(found && (*resultType != kSecTrustSettingsResultUnspecified)) {
			trustSettingsDbg("SecTrustSettingsEvaluateCert: found in domain %d", domain);
			*foundAnyEntry = true;
			*foundMatchingEntry = true;
			return errSecSuccess;
		}
		foundAny |= foundAnyHere;
	}
	trustSettingsDbg("SecTrustSettingsEvaluateCert: NOT FOUND");
	*foundAnyEntry = foundAny;
	*foundMatchingEntry = false;
	return errSecSuccess;
	END_RCSAPI
}

/*
 * Obtain trusted certs which match specified usage.
 * Only certs with a SecTrustSettingsResult of
 * kSecTrustSettingsResultTrustRoot or
 * or kSecTrustSettingsResultTrustAsRoot will be returned.
 * To be used by SecureTransport for its SSLSetTrustedRoots() call;
 * I hope nothing else has to use this...
 * Caller must CFRelease the returned CFArrayRef.
 */
OSStatus SecTrustSettingsCopyQualifiedCerts(
	const CSSM_OID				*policyOID,
	const char					*policyString,		/* optional */
	uint32						policyStringLen,
	SecTrustSettingsKeyUsage	keyUsage,			/* optional */
	CFArrayRef					*certArray)			/* RETURNED */
{
	BEGIN_RCSAPI

	/* ensure a NULL_terminated string */
	auto_array<char> polStr;
	if(policyString != NULL) {
		polStr.allocate(policyStringLen + 1);
		memmove(polStr.get(), policyString, policyStringLen);
		if(policyString[policyStringLen - 1] != '\0') {
			(polStr.get())[policyStringLen] = '\0';
		}
	}

	return tsCopyCertsCommon(policyOID, polStr.get(), keyUsage,
		false,				/* !onlyRoots */
		true, true, true,	/* all domains */
		certArray);

	END_RCSAPI
}

/*
 * Obtain unrestricted root certs from the specified domain(s).
 * Only returns roots with no usage constraints.
 * Caller must CFRelease the returned CFArrayRef.
 */
OSStatus SecTrustSettingsCopyUnrestrictedRoots(
	Boolean					user,
	Boolean					admin,
	Boolean					system,
	CFArrayRef				*certArray)		/* RETURNED */
{
	BEGIN_RCSAPI

	OSStatus status = tsCopyCertsCommon(NULL, NULL, NULL,	/* no constraints */
		true,				/* onlyRoots */
		user, admin, system,
		certArray);

    return status;

	END_RCSAPI
}

static const char hexChars[16] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

/*
 * Obtain a string representing a cert's SHA1 digest. This string is
 * the key used to look up per-cert trust settings in a TrustSettings record.
 */
CFStringRef SecTrustSettingsCertHashStrFromCert(
	SecCertificateRef certRef)
{
	if(certRef == NULL) {
		return NULL;
	}

	if(certRef == kSecTrustSettingsDefaultRootCertSetting) {
		/* use this string instead of the cert hash as the dictionary key */
		trustSettingsDbg("SecTrustSettingsCertHashStrFromCert: DefaultSetting");
        secerror("Caller passed kSecTrustSettingsDefaultRootCertSetting. This constant is deprecated and no longer affects the behavior of the system.");
		return kSecTrustRecordDefaultRootCert;
	}

	CSSM_DATA certData;
	OSStatus ortn = SecCertificateGetData(certRef, &certData);
	if(ortn) {
		return NULL;
	}
	return SecTrustSettingsCertHashStrFromData(certData.Data, certData.Length);
}

CFStringRef SecTrustSettingsCertHashStrFromData(
	const void *cert,
	size_t certLen)
{
	unsigned char digest[CC_SHA1_DIGEST_LENGTH];
	char asciiDigest[(2 * CC_SHA1_DIGEST_LENGTH) + 1];
	unsigned dex;
	char *outp = asciiDigest;
	unsigned char *inp = digest;

	if(cert == NULL) {
		return NULL;
	}

	CC_SHA1(cert, (CC_LONG)certLen, digest);

	for(dex=0; dex<CC_SHA1_DIGEST_LENGTH; dex++) {
		unsigned c = *inp++;
		outp[1] = hexChars[c & 0xf];
		c >>= 4;
		outp[0] = hexChars[c];
		outp += 2;
	}
	*outp = 0;
	return CFStringCreateWithCString(NULL, asciiDigest, kCFStringEncodingASCII);
}

/*
 * Add a cert's TrustSettings to a non-persistent TrustSettings record.
 * No locking or cache flushing here; it's all local to the TrustSettings
 * we construct here.
 */
OSStatus SecTrustSettingsSetTrustSettingsExternal(
	CFDataRef			settingsIn,					/* optional */
	SecCertificateRef	certRef,					/* optional */
	CFTypeRef			trustSettingsDictOrArray,	/* optional */
	CFDataRef			*settingsOut)				/* RETURNED */
{
	BEGIN_RCSAPI

	TS_REQUIRED(settingsOut)

	OSStatus result;
	TrustSettings* ts;

	result = TrustSettings::CreateTrustSettings((SecTrustSettingsDomain)kSecTrustSettingsDomainMemory, settingsIn, ts);
	if (result != errSecSuccess) {
		return result;
	}

	unique_ptr<TrustSettings>_(ts);

	if(certRef != NULL) {
		ts->setTrustSettings(certRef, trustSettingsDictOrArray);
	}
	*settingsOut = ts->createExternal();
	return errSecSuccess;

	END_RCSAPI
}

void SecTrustSettingsPurgeCache(void) {
    tsPurgeCache();
}

OSStatus SecTrustSettingsCopyTrustSettings_Cached(
    SecCertificateRef certRef,
    SecTrustSettingsDomain domain,
    CFArrayRef CF_RETURNS_RETAINED *trustSettings)                /* RETURNED */
{
    TS_REQUIRED(certRef)
    TS_REQUIRED(trustSettings)

    OSStatus result = tsCopyTrustSettings_cached(certRef, domain, trustSettings);
    if (result == errSecSuccess && *trustSettings == NULL) {
        result = errSecItemNotFound; /* documented result if no trust settings exist */
    }
    return result;
}

#pragma mark --- API functions ---

OSStatus SecTrustSettingsCopyTrustSettings(
	SecCertificateRef certRef,
	SecTrustSettingsDomain domain,
	CFArrayRef *trustSettings)				/* RETURNED */
{
	TS_REQUIRED(certRef)
	TS_REQUIRED(trustSettings)

	OSStatus result = tsCopyTrustSettings(certRef, domain, trustSettings, NULL);
	if (result == errSecSuccess && *trustSettings == NULL) {
		result = errSecItemNotFound; /* documented result if no trust settings exist */
	}
	return result;
}

OSStatus SecTrustSettingsCopyModificationDate(
	SecCertificateRef		certRef,
	SecTrustSettingsDomain	domain,
	CFDateRef				*modificationDate)	/* RETURNED */
{
	TS_REQUIRED(certRef)
	TS_REQUIRED(modificationDate)

	OSStatus result = tsCopyTrustSettings(certRef, domain, NULL, modificationDate);
	if (result == errSecSuccess && *modificationDate == NULL) {
		result = errSecItemNotFound; /* documented result if no trust settings exist */
	}
	return result;
}

/* works with existing and with new cert */
OSStatus SecTrustSettingsSetTrustSettings(
	SecCertificateRef certRef,
	SecTrustSettingsDomain domain,
	CFTypeRef trustSettingsDictOrArray)
{
	BEGIN_RCSAPI

	TS_REQUIRED(certRef)

	if(domain == kSecTrustSettingsDomainSystem) {
		return errSecDataNotModifiable;
	}

	OSStatus result;
	TrustSettings* ts;

	result = TrustSettings::CreateTrustSettings(domain, CREATE_YES, TRIM_NO, ts);
	if (result != errSecSuccess) {
		return result;
	}

	unique_ptr<TrustSettings>_(ts);

	ts->setTrustSettings(certRef, trustSettingsDictOrArray);
	ts->flushToDisk(certRef, trustSettingsDictOrArray);
	tsTrustSettingsChanged();
	return errSecSuccess;

	END_RCSAPI
}

OSStatus SecTrustSettingsRemoveTrustSettings(
	SecCertificateRef cert,
	SecTrustSettingsDomain domain)
{
	BEGIN_RCSAPI

	TS_REQUIRED(cert)

	if(domain == kSecTrustSettingsDomainSystem) {
		return errSecDataNotModifiable;
	}

	OSStatus result;
	TrustSettings* ts;

	result = TrustSettings::CreateTrustSettings(domain, CREATE_NO, TRIM_NO, ts);
	if (result != errSecSuccess) {
		return result;
	}

	unique_ptr<TrustSettings>_(ts);

	/* deleteTrustSettings throws if record not found */
	trustSettingsDbg("SecTrustSettingsRemoveTrustSettings: deleting from domain %d",
		(int)domain);
	ts->deleteTrustSettings(cert);
	ts->flushToDisk(cert, NULL);
	tsTrustSettingsChanged();
	return errSecSuccess;

	END_RCSAPI
}

/* get all certs listed in specified domain */
static OSStatus SecTrustSettingsCopyCertificates_internal(
	SecTrustSettingsDomain	domain,
	CFArrayRef				*certArray)
{
	BEGIN_RCSAPI

	TS_REQUIRED(certArray)

	OSStatus status;
	TrustSettings* ts;
	CFMutableArrayRef trustedCertArray = NULL;
    SecTrustRef trust = NULL;

	status = TrustSettings::CreateTrustSettings(domain, CREATE_NO, TRIM_NO, ts);
	if (status != errSecSuccess) {
		return status;
	}

	unique_ptr<TrustSettings>_(ts);

	CFMutableArrayRef outArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	/*
	 * Keychains to search: user's search list, System.keychain, system root store
	 */
	StorageManager::KeychainList keychains;
	Keychain adminKc;
	Keychain sysRootKc;
	switch(domain) {
		case kSecTrustSettingsDomainUser:
			/* user search list */
			try {
				globals().storageManager.getSearchList(keychains);
			}
			catch (const CommonError &err) {
				/* if we fail to read user keychains, we still want to search the admin & system stores */
				secnotice("trustsettings", "SecTrustSettingsCopyCertificates: handling error %ld for user domain", (long)err.osStatus());
			}
			[[fallthrough]];
		case kSecTrustSettingsDomainAdmin:
			/* admin certs in system keychain */
			try {
				adminKc = globals().storageManager.make(ADMIN_CERT_STORE_PATH, false);
				keychains.push_back(adminKc);
			}
			catch (const CommonError &err) {
				/* if we fail to read the system keychain, we still want to get the system root store */
				secnotice("trustsettings", "SecTrustSettingsCopyCertificates: handling error %ld for admin domain", (long)err.osStatus());
			}
			[[fallthrough]];
		case kSecTrustSettingsDomainSystem:
			/* and, for all cases, immutable system root store */
			sysRootKc = globals().storageManager.make(SYSTEM_ROOT_STORE_PATH, false);
			keychains.push_back(sysRootKc);
            break;
		default:
			/* already validated when we created the TrustSettings */
			break;
	}
	ts->findCerts(keychains, outArray);
    CFIndex count = outArray ? CFArrayGetCount(outArray) : 0;
	if(count == 0) {
		CFReleaseSafe(outArray);
		return errSecNoTrustSettings;
	}
 /* Go through outArray and do a SecTrustEvaluate only for DomainSystem */
	if (kSecTrustSettingsDomainSystem == domain) {
        CFIndex i;
        SecPolicyRef policy = SecPolicyCreateBasicX509();
	    trustedCertArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
        for (i = 0; i < count ; i++) {
            SecTrustResultType result;
            SecCertificateRef certificate = (SecCertificateRef) CFArrayGetValueAtIndex(outArray, i);
            status = SecTrustCreateWithCertificates(certificate, policy, &trust);
        	if (status != errSecSuccess) {
               CFReleaseSafe(policy);
     	       goto out;
            }
            status = SecTrustEvaluate(trust, &result);
            if (status != errSecSuccess) {
               CFReleaseSafe(policy);
               goto out;
            }
            if (result != kSecTrustResultFatalTrustFailure) {
                CFArrayAppendValue(trustedCertArray, certificate);
            }
            CFReleaseNull(trust);
        }
		tsAddConditionalCerts(trustedCertArray);
        if (CFArrayGetCount(trustedCertArray) == 0) {
			status = errSecNoTrustSettings;
		} else {
			*certArray = trustedCertArray;
			CFReleaseSafe(outArray);
		}
		CFReleaseSafe(policy);
	} else {
		*certArray = outArray;
    }
out:
    if (status != errSecSuccess) {
        CFReleaseSafe(outArray);
		CFReleaseSafe(trustedCertArray);
     }
    CFReleaseNull(trust);
    return status;
	END_RCSAPI
}

/* get all certs listed in specified domain */
OSStatus SecTrustSettingsCopyCertificates(
    SecTrustSettingsDomain    domain,
    CFArrayRef                *certArray)
{
    // To avoid a deadlock when reading the certificates unexpectedly requires
    // trust evaluation, we dispatch this work and wait up to 5 seconds for it.
    static dispatch_queue_t sCopyCertificatesQueue;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sCopyCertificatesQueue = dispatch_queue_create("copy_certificates_from_keychain", DISPATCH_QUEUE_SERIAL);
    });
    __block OSStatus result = 0;
    __block CFArrayRef localArray = NULL;
    __block bool mustReleaseArray = false;
    dispatch_block_t actuallyRunIt = dispatch_block_create((dispatch_block_flags_t) 0, ^{
        result = SecTrustSettingsCopyCertificates_internal(domain, &localArray);
        if (mustReleaseArray) {
            // we have timed out, so there is nobody to consume this array
            CFReleaseNull(localArray);
        }
    });

    dispatch_time_t interval = NSEC_PER_SEC * 5;
    dispatch_async(sCopyCertificatesQueue, actuallyRunIt);
    if (dispatch_block_wait(actuallyRunIt, dispatch_time(DISPATCH_TIME_NOW, interval)) != 0) {
        secerror("SecTrustSettingsCopyCertificates: timed out!");
        mustReleaseArray = true;
        result = errSecIO;
    } else if (certArray) {
        *certArray = localArray;
    } else {
        CFReleaseNull(localArray);
    }
    Block_release(actuallyRunIt);
    return result;
}

static CFArrayRef gUserAdminCerts = NULL;
static bool gUserAdminCertsCacheBuilt = false;
static ModuleNexus<ReadWriteLock> gUserAdminCertsLock;

void SecTrustSettingsPurgeUserAdminCertsCache(void) {
    StReadWriteLock _(gUserAdminCertsLock(), StReadWriteLock::Write);
    CFReleaseNull(gUserAdminCerts);
    gUserAdminCertsCacheBuilt = false;
}

OSStatus SecTrustSettingsCopyCertificatesForUserAdminDomains(
                                                             CFArrayRef  *certArray)
{
    TS_REQUIRED(certArray);
    OSStatus result = errSecSuccess;

    { /* Hold the read lock for the check */
        StReadWriteLock _(gUserAdminCertsLock(), StReadWriteLock::Read);
        if (gUserAdminCertsCacheBuilt) {
            if (gUserAdminCerts) {
                *certArray = (CFArrayRef)CFRetain(gUserAdminCerts);
                return errSecSuccess;
            } else {
                return errSecNoTrustSettings;
            }
        }
    }

    /* There were no cached results. We'll have to recreate them. */
    CFMutableArrayRef outArray = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (!outArray) {
        return errSecAllocate;
    }

    CFArrayRef userTrusted = NULL, adminTrusted = NULL;
    OSStatus userStatus = SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainUser, &userTrusted);
    if ((userStatus == errSecSuccess) && (userTrusted != NULL)) {
        CFArrayAppendArray(outArray, userTrusted, CFRangeMake(0, CFArrayGetCount(userTrusted)));
        CFRelease(userTrusted);
    }

    OSStatus adminStatus = SecTrustSettingsCopyCertificates(kSecTrustSettingsDomainAdmin, &adminTrusted);
    if ((adminStatus == errSecSuccess) && (adminTrusted != NULL)) {
        CFArrayAppendArray(outArray, adminTrusted, CFRangeMake(0, CFArrayGetCount(adminTrusted)));
        CFRelease(adminTrusted);
    }

    /* Lack of trust settings for a domain results in an error above. Only fail
     * if we weren't able to get trust settings for both domains. */
    if (userStatus != errSecSuccess && adminStatus != errSecSuccess) {
        result = userStatus;
    }

    if (result != errSecSuccess && outArray) {
        CFRelease(outArray);
        outArray = NULL;
    }

    *certArray = outArray;

    /* For valid results, update the global cache */
    if (result == errSecSuccess || result == errSecNoTrustSettings) {
        StReadWriteLock _(gUserAdminCertsLock(), StReadWriteLock::Write);
        CFReleaseNull(gUserAdminCerts);
        gUserAdminCerts = (CFArrayRef)CFRetainSafe(outArray);
        gUserAdminCertsCacheBuilt = true;
    }

    return result;
}

bool SecTrustSettingsUserAdminDomainsContain(SecCertificateRef certRef)
{
    TS_REQUIRED(certRef)
    if (tsContains(certRef, kSecTrustSettingsDomainAdmin) == errSecSuccess ||
        tsContains(certRef, kSecTrustSettingsDomainUser) == errSecSuccess) {
        return true;
    }
    return false;
}

/*
 * Obtain an external, portable representation of the specified
 * domain's TrustSettings. Caller must CFRelease the returned data.
 */
OSStatus SecTrustSettingsCreateExternalRepresentation(
	SecTrustSettingsDomain	domain,
	CFDataRef				*trustSettings)
{
	BEGIN_RCSAPI

	TS_REQUIRED(trustSettings)

	OSStatus result;
	TrustSettings* ts;

	result = TrustSettings::CreateTrustSettings(domain, CREATE_NO, TRIM_NO, ts);
	if (result != errSecSuccess) {
		return result;
	}

	unique_ptr<TrustSettings>_(ts);

	*trustSettings = ts->createExternal();
	return errSecSuccess;

	END_RCSAPI
}

/*
 * Import trust settings, obtained via SecTrustSettingsCreateExternalRepresentation,
 * into the specified domain.
 */
OSStatus SecTrustSettingsImportExternalRepresentation(
	SecTrustSettingsDomain	domain,
	CFDataRef				trustSettings)		/* optional - NULL means empty settings */
{
	BEGIN_RCSAPI

	if(domain == kSecTrustSettingsDomainSystem) {
		return errSecDataNotModifiable;
	}

	OSStatus result;
	TrustSettings* ts;

	result = TrustSettings::CreateTrustSettings(domain, trustSettings, ts);
	if (result != errSecSuccess) {
		return result;
	}

	unique_ptr<TrustSettings>_(ts);

	ts->flushToDisk(NULL, NULL);
	tsTrustSettingsChanged();
	return errSecSuccess;

	END_RCSAPI
}

/*
 * SecTrustSettingsSetTrustSettings convenience wrapper function.
 */
void SecTrustSettingsSetTrustedCertificateForSSLHost(
    SecCertificateRef certificate,
    CFStringRef hostname,
    void (^result)(SecTrustSettingsResult trustResult, CFErrorRef error))
{
	__block CFMutableArrayRef trustSettings = NULL;
	__block CFNumberRef trustSettingsResult = NULL;
	__block SecTrustSettingsDomain domain = kSecTrustSettingsDomainUser;

	CFDictionaryRef policyProperties = NULL;
	CFStringRef policyOid = NULL;
	SecPolicyRef policy = NULL;

	Boolean isSelfSigned = false;
	Boolean hasPolicyConstraint = false;
	Boolean hasPolicyValue = false;
	Boolean policyConstraintChanged = false;
	CFIndex indexOfEntryWithAllowedErrorForExpiredCert = kCFNotFound;
	CFIndex indexOfEntryWithAllowedErrorForHostnameMismatch = kCFNotFound;
	CFIndex i, count;
	int32_t trustSettingsResultCode = kSecTrustSettingsResultTrustAsRoot;
	OSStatus status = errSecSuccess;

	CFRetainSafe(certificate);
	CFRetainSafe(hostname);
	if (!certificate || !hostname) {
		status = errSecParam;
	} else {
		status = SecCertificateIsSelfSigned(certificate, &isSelfSigned);
	}
	if (status != errSecSuccess) {
		goto reportErr;
	}
	if (isSelfSigned) {
		trustSettingsResultCode = kSecTrustSettingsResultTrustRoot;
	}
	trustSettingsResult = CFNumberCreate(NULL, kCFNumberSInt32Type, &trustSettingsResultCode);

	/* start with the existing trust settings for this certificate, if any */
	{
		CFArrayRef curTrustSettings = NULL;
		(void)SecTrustSettingsCopyTrustSettings(certificate, domain, &curTrustSettings);
		if (curTrustSettings) {
			trustSettings = CFArrayCreateMutableCopy(NULL, 0, curTrustSettings);
			CFReleaseNull(curTrustSettings);
		} else {
			trustSettings = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
		}
	}
	if (!trustSettings || !trustSettingsResult) {
		status = errSecAllocate;
		goto reportErr;
	}

	/* set up policy and value instances to trust the certificate for SSL for a given hostname */
	policy = SecPolicyCreateSSL(true, hostname);
	if (!policy) {
		status = errSecInternal;
		goto reportErr;
	}
	policyProperties = SecPolicyCopyProperties(policy);
	if (!policyProperties) {
		status = errSecInternal;
		goto reportErr;
	}
	policyOid = (CFStringRef)CFDictionaryGetValue(policyProperties, kSecPolicyOid);
	CFRetainSafe(policyOid);
	if (!policyOid) {
		status = errSecInternal;
		goto reportErr;
	}

	/* look for dictionaries in the trust settings array for this policy and value */
	count = CFArrayGetCount(trustSettings);
	for (i=0; i < count; i++) {
		CFDictionaryRef constraints = (CFDictionaryRef)CFArrayGetValueAtIndex(trustSettings, i);
		if (!constraints) { continue; }
		SecPolicyRef aPolicy = (SecPolicyRef)CFDictionaryGetValue(constraints, kSecTrustSettingsPolicy);
		if (!aPolicy) { continue; }
		CFDictionaryRef properties = SecPolicyCopyProperties(aPolicy);
		if (!properties) { continue; }
		CFStringRef aPolicyOid = (CFStringRef)CFDictionaryGetValue(properties, kSecPolicyOid);
		if (aPolicyOid && kCFCompareEqualTo == CFStringCompare(aPolicyOid, policyOid, 0)) {
			CFStringRef aPolicyString = (CFStringRef)CFDictionaryGetValue(constraints, kSecTrustSettingsPolicyString);
			if (aPolicyString && kCFCompareEqualTo == CFStringCompare(aPolicyString, hostname, kCFCompareCaseInsensitive)) {
				/* found existing entry */
				CFNumberRef allowedErr = (CFNumberRef)CFDictionaryGetValue(constraints, kSecTrustSettingsAllowedError);
				int32_t eOld = 0;
				if (!allowedErr || !CFNumberGetValue(allowedErr, kCFNumberSInt32Type, &eOld)) {
					eOld = CSSM_OK;
				}
				CFNumberRef tsResult = (CFNumberRef)CFDictionaryGetValue(constraints, kSecTrustSettingsResult);
				int32_t rOld = 0;
				if (!tsResult || !CFNumberGetValue(allowedErr, kCFNumberSInt32Type, &rOld)) {
					rOld = kSecTrustSettingsResultTrustRoot;
				}
				if (!hasPolicyValue) { hasPolicyValue = (aPolicyString != NULL); }
				if (!hasPolicyConstraint) { hasPolicyConstraint = true; }
				if (eOld == CSSMERR_TP_CERT_EXPIRED) {
					indexOfEntryWithAllowedErrorForExpiredCert = i;
				} else if (eOld == CSSMERR_APPLETP_HOSTNAME_MISMATCH) {
					indexOfEntryWithAllowedErrorForHostnameMismatch = i;
				}
				if (trustSettingsResultCode != rOld) {
					policyConstraintChanged = true;  // we are changing existing policy constraint's result
				}
			}
		}
		CFReleaseSafe(properties);
	}

	if (!hasPolicyConstraint) {
		policyConstraintChanged = true; // we are adding a new policy constraint
	} else if (hostname && !hasPolicyValue) {
		policyConstraintChanged = true; // we need to add the hostname to an existing policy constraint
	} else if ((indexOfEntryWithAllowedErrorForExpiredCert == kCFNotFound) ||
			   (indexOfEntryWithAllowedErrorForHostnameMismatch == kCFNotFound)) {
		policyConstraintChanged = true; // we are missing one of the expected allowed-error entries for this policy
	}

	if (policyConstraintChanged) {
		CFMutableDictionaryRef policyDict[2] = { NULL, NULL };
		policyDict[0] = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		policyDict[1] = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
		int32_t certExpiredCode = (int32_t)CSSMERR_TP_CERT_EXPIRED;
		CFNumberRef certExpired = CFNumberCreate(NULL, kCFNumberSInt32Type, &certExpiredCode);
		int32_t hostnameMismatchCode = (int32_t)CSSMERR_APPLETP_HOSTNAME_MISMATCH;
		CFNumberRef hostnameMismatch = CFNumberCreate(NULL, kCFNumberSInt32Type, &hostnameMismatchCode);
		if (!policyDict[0] || !policyDict[1] || !certExpired || !hostnameMismatch) {
			status = errSecInternal;
		} else {
			/* set up entry for policy, hostname, expired cert error, and result */
			CFDictionarySetValue(policyDict[0], kSecTrustSettingsPolicy, policy);
			CFDictionarySetValue(policyDict[0], kSecTrustSettingsPolicyString, hostname);
			CFDictionarySetValue(policyDict[0], kSecTrustSettingsAllowedError, certExpired);
			CFDictionarySetValue(policyDict[0], kSecTrustSettingsResult, trustSettingsResult);
			if (indexOfEntryWithAllowedErrorForExpiredCert != kCFNotFound) {
				/* if we found an existing constraint for this policy, hostname, and allowed error, replace it */
				CFArraySetValueAtIndex(trustSettings, indexOfEntryWithAllowedErrorForExpiredCert, policyDict[0]);
			} else if (!(hasPolicyValue)) {
				/* add a new policy constraint */
				CFArrayAppendValue(trustSettings, policyDict[0]);
			}
			/* set up additional entry for policy, hostname, hostname mismatch error, and result */
			CFDictionarySetValue(policyDict[1], kSecTrustSettingsPolicy, policy);
			CFDictionarySetValue(policyDict[1], kSecTrustSettingsPolicyString, hostname);
			CFDictionarySetValue(policyDict[1], kSecTrustSettingsAllowedError, hostnameMismatch);
			CFDictionarySetValue(policyDict[1], kSecTrustSettingsResult, trustSettingsResult);
			if (indexOfEntryWithAllowedErrorForHostnameMismatch != kCFNotFound) {
				/* if we found an existing constraint for this policy, hostname, and allowed error, replace it */
				CFArraySetValueAtIndex(trustSettings, indexOfEntryWithAllowedErrorForHostnameMismatch, policyDict[1]);
			} else if (!(hasPolicyValue)) {
				/* add a new policy constraint */
				CFArrayAppendValue(trustSettings, policyDict[1]);
			}
		}
		CFReleaseSafe(policyDict[0]);
		CFReleaseSafe(policyDict[1]);
		CFReleaseSafe(certExpired);
		CFReleaseSafe(hostnameMismatch);
	}

	if (status != errSecSuccess) {
		goto reportErr;
	}
	CFReleaseSafe(policyOid);
	CFReleaseSafe(policyProperties);
	CFReleaseSafe(policy);

	dispatch_async(dispatch_get_main_queue(), ^{
		/* add certificate to keychain first */
		OSStatus status = SecCertificateAddToKeychain(certificate, NULL);
		if (status == errSecSuccess || status == errSecDuplicateItem) {
			/* this will block on authorization UI... */
			status = SecTrustSettingsSetTrustSettings(certificate,
				domain, trustSettings);
		}
		if (result) {
			CFErrorRef error = NULL;
			if (status) {
				error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
			}
			int32_t tsrc;
			if (!CFNumberGetValue(trustSettingsResult, kCFNumberSInt32Type, (int32_t*)&tsrc)) {
				tsrc = (int32_t)kSecTrustSettingsResultUnspecified;
			}
			result((SecTrustSettingsResult)tsrc, error);
			CFReleaseSafe(error);
		}
		CFRelease(trustSettingsResult);
		CFRelease(trustSettings);
		CFRelease(certificate);
		CFRelease(hostname);
	});

	return;

reportErr:
	CFReleaseSafe(policyOid);
	CFReleaseSafe(policyProperties);
	CFReleaseSafe(policy);
	CFReleaseSafe(trustSettingsResult);
	CFReleaseSafe(trustSettings);
	CFReleaseSafe(certificate);
	CFReleaseSafe(hostname);
	if (result) {
		CFErrorRef error = CFErrorCreate(NULL, kCFErrorDomainOSStatus, status, NULL);
		result(kSecTrustSettingsResultInvalid, error);
		CFReleaseSafe(error);
	}
}
