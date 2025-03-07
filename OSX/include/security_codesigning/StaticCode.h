/*
 * Copyright (c) 2006-2014 Apple Inc. All Rights Reserved.
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

//
// StaticCode - SecStaticCode API objects
//
#ifndef _H_STATICCODE
#define _H_STATICCODE

#include "cs.h"
#include "csutilities.h"
#include "Requirements.h"
#include "requirement.h"
#include "diskrep.h"
#include "codedirectory.h"
#include <Security/SecTrust.h>
#include <CoreFoundation/CFData.h>
#include <security_utilities/dispatch.h>
#include <CoreEntitlements/CoreEntitlements.h>

namespace Security {
namespace CodeSigning {


class SecCode;


//
// A SecStaticCode object represents the file system version of some code.
// There's a lot of pieces to this, and we'll bring them all into
// memory here (lazily) and let you fondle them with ease.
//
// Note that concrete knowledge of where stuff is stored resides in the DiskRep
// object we hold. DiskReps allocate, retrieve, and return data to us. We are
// responsible for interpreting, caching, and validating them. (In other words,
// DiskReps know where stuff is and how it is stored, but we know what it means.)
//
// Data accessors (returning CFDataRef, CFDictionaryRef, various pointers, etc.)
// cache those values internally and return unretained(!) references ("Get" style)
// that are valid as long as the SecStaticCode object's lifetime, or until
// resetValidity() is called, whichever is sooner. If you need to keep them longer,
// retain or copy them as needed. None of these data accessors are thread-safe, so
// be careful using them.
//
class SecStaticCode : public SecCFObject {
	NOCOPY(SecStaticCode)
	
protected:
	//
	// A context for resource validation operations, to tailor error response.
	// The base class throws an exception immediately and ignores detail data.
	// 
	class ValidationContext {
	public:
		ValidationContext(SecStaticCode &c) : code(c) { }
		virtual ~ValidationContext();
		virtual void reportProblem(OSStatus rc, CFStringRef type, CFTypeRef value);
		
		virtual OSStatus osStatus()	{ return noErr; }
		virtual void throwMe()		{ }
		
		SecStaticCode &code;
	};
	
	//
	// A CollectingContext collects all error details and throws an annotated final error.
	//
	class CollectingContext : public ValidationContext {
	public:
		CollectingContext(SecStaticCode &c) : ValidationContext(c), mStatus(errSecSuccess) { }
		void reportProblem(OSStatus rc, CFStringRef type, CFTypeRef value);
		
		OSStatus osStatus()		{ return mStatus; }
		operator OSStatus () const		{ return mStatus; }
		void throwMe() __attribute__((noreturn));

	private:
		CFRef<CFMutableDictionaryRef> mCollection;
		OSStatus mStatus;
		Mutex mLock;
	};

public:
	SECCFFUNCTIONS(SecStaticCode, SecStaticCodeRef,
		errSecCSInvalidObjectRef, gCFObjects().StaticCode)
	
	// implicitly convert SecCodeRefs to their SecStaticCodeRefs
	static SecStaticCode *requiredStatic(SecStaticCodeRef ref);	// convert SecCodeRef
	static SecCode *optionalDynamic(SecStaticCodeRef ref); // extract SecCodeRef or NULL if static

	SecStaticCode(DiskRep *rep, uint32_t flags = 0);
    virtual ~SecStaticCode() _NOEXCEPT;

    void initializeFromParent(const SecStaticCode& parent);

    bool equal(SecCFObject &other);
    CFHashCode hash();
	
	void detachedSignature(CFDataRef sig);		// attach an explicitly given detached signature
	void checkForSystemSignature();				// check for and attach system-supplied detached signature

	typedef std::map<CodeDirectory::HashAlgorithm, CFCopyRef<CFDataRef> > CodeDirectoryMap;

	const CodeDirectory *codeDirectory(bool check = true) const;
	const CodeDirectoryMap *codeDirectories(bool check = true) const;
	CodeDirectory::HashAlgorithm hashAlgorithm() const { return codeDirectory()->hashType; }
	CodeDirectory::HashAlgorithms hashAlgorithms() const { return mHashAlgorithms; }
	CFDataRef cdHash();
	CFArrayRef cdHashes();
	CFDictionaryRef cdHashesFull();
	CFDataRef signature();
	CFAbsoluteTime signingTime();
	CFAbsoluteTime signingTimestamp();
	bool isSigned() { return codeDirectory(false) != NULL; }
	DiskRep *diskRep() const { return mRep; }
	bool isDetached() const { return mRep->base() != mRep; }
	std::string mainExecutablePath() { return mRep->mainExecutablePath(); }
	CFURLRef copyCanonicalPath() const { return mRep->copyCanonicalPath(); }
	std::string identifier() { return codeDirectory()->identifier(); }
	const char *teamID() { return codeDirectory()->teamID(); }
	std::string format() const { return mRep->format(); }
	std::string signatureSource();
 	virtual CFDataRef component(CodeDirectory::SpecialSlot slot, OSStatus fail = errSecCSSignatureFailed);
 	virtual CFDictionaryRef infoDictionary();
	CFDictionaryRef copyDiskRepInformation();

	CFDictionaryRef entitlements();
	CFDataRef copyComponent(CodeDirectory::SpecialSlot slot, CFDataRef hash);

	CFDictionaryRef resourceDictionary(bool check = true);
	CFURLRef resourceBase();
	void validateResource(CFDictionaryRef files, std::string path, bool isSymlink, ValidationContext &ctx, SecCSFlags flags, uint32_t version);
	void validateSymlinkResource(std::string fullpath, std::string seal, ValidationContext &ctx, SecCSFlags flags);

	bool flag(uint32_t tested);

	SecCodeCallback monitor() const { return mMonitor; }
	void setMonitor(SecCodeCallback monitor) { mMonitor = monitor; }
	CFTypeRef reportEvent(CFStringRef stage, CFDictionaryRef info);
	void reportProgress(unsigned amount = 1);

	SecCSFlags getFlags() { return mFlags; }
	void setFlags(SecCSFlags flags) { mFlags = flags; }
	void setValidationFlags(SecCSFlags flags) { mValidationFlags = flags; }
	void setValidationModifiers(CFDictionaryRef modifiers);
	
	void resetValidity();						// clear validation caches (if something may have changed)
	
	bool validated() const	{ return mValidated; }
	bool revocationChecked() const { return mRevocationChecked; }
	bool valid() const
		{ assert(validated()); return mValidated && (mValidationResult == errSecSuccess); }
	bool validatedExecutable() const	{ return mExecutableValidated; }
	bool validatedResources() const	{ return mResourcesValidated; }

	void prepareProgress(unsigned workload);
	void cancelValidation();

	void validateDirectory();
	virtual void validateComponent(CodeDirectory::SpecialSlot slot, OSStatus fail = errSecCSSignatureFailed);
	void validateNonResourceComponents();
	void validateTopDirectory();
	unsigned estimateResourceWorkload();
	void validateResources(SecCSFlags flags);
	void validateExecutable();
	void validateNestedCode(CFURLRef path, const ResourceSeal &seal, SecCSFlags flags, bool isFramework);
	void checkRevocationOnNestedBinary(UnixPlusPlus::FileDesc &fd, CFURLRef url, SecCSFlags flags);
	bool validationCannotUseNetwork();
	
	void validatePlainMemoryResource(string path, CFDataRef fileData, SecCSFlags flags);
	
	const Requirements *internalRequirements();
	const Requirement *internalRequirement(SecRequirementType type);
	const Requirement *designatedRequirement();
	const Requirement *defaultDesignatedRequirement();		// newly allocated (caller owns)

	unsigned int validationCategory();
	bool inLoadedTrustCache();
	CFDictionaryRef defaultDesignatedLightWeightCodeRequirement();
	
	void validateRequirements(SecRequirementType type, SecStaticCode *target,
		OSStatus nullError = errSecSuccess);										// target against my [type], throws
	void validateRequirement(const Requirement *req, OSStatus failure);		// me against [req], throws
	bool satisfiesRequirement(const Requirement *req, OSStatus failure);	// me against [req], returns on clean miss
	
	// certificates are available after signature validation (they are stored in the CMS signature)
	SecCertificateRef cert(int ix);		// get a cert from the cert chain
	CFArrayRef certificates();			// get the entire certificate chain
	
	CFDictionaryRef signingInformation(SecCSFlags flags); // omnibus information-gathering API (creates new dictionary)

	static bool isAppleDeveloperCert(CFArrayRef certs); // determines if this is an apple developer certificate for library validation
    bool trustedSigningCertChain() { return mTrustedSigningCertChain; }

	void handleOtherArchitectures(void (^handle)(SecStaticCode* other));
	void visitOtherArchitectures(void (^visitor)(SecStaticCode* other));

	uint8_t cmsDigestHashType() const { return mCMSDigestHashType; };
	CFDataRef createCmsDigest();
public:
	void staticValidate(SecCSFlags flags, const SecRequirement *req);
	void staticValidateCore(SecCSFlags flags, const SecRequirement *req);
	void staticValidateResource(string resourcePath, SecCSFlags flags, const SecRequirement *req);
	
protected:
	bool loadCodeDirectories(CodeDirectoryMap& cdMap) const;
	
protected:
	CFDictionaryRef getDictionary(CodeDirectory::SpecialSlot slot, bool check = true); // component value as a dictionary
	bool verifySignature();
	CFArrayRef createVerificationPolicies();
	CFArrayRef createTimeStampingAndRevocationPolicies();
	
	// load preferred rules/files dictionaries (cached therein)
	bool loadResources(CFDictionaryRef& rules, CFDictionaryRef& files, uint32_t& version);

	static void checkOptionalResource(CFTypeRef key, CFTypeRef value, void *context);
	bool hasWeakResourceRules(CFDictionaryRef rulesDict, uint32_t version, CFArrayRef allowedOmissions);

private:
	void validateOtherVersions(CFURLRef path, SecCSFlags flags, SecRequirementRef req, SecStaticCode *code);
	bool checkfix30814861(string path, bool addition);
	bool checkfix41082220(OSStatus result);
	CFArrayRef copyCertChain(SecTrustRef trust);

	ResourceBuilder *mCheckfix30814861builder1;
	dispatch_once_t mCheckfix30814861builder1_once;
	
private:
	static const uint8_t mCMSDigestHashType = kSecCodeSignatureHashSHA256;
										// hash of CMS digest (kSecCodeSignatureHash* constant)
	RefPointer<DiskRep> mRep;			// on-disk representation
	mutable CodeDirectoryMap mCodeDirectories; // available CodeDirectory blobs by digest type
	mutable CFRef<CFDataRef> mBaseDir;	// the primary CodeDirectory blob (whether it's chosen or not)
	CFRef<CFDataRef> mDetachedSig;		// currently applied explicit detached signature
	
	// private validation modifiers (only used by Gatekeeper checkfixes)
	MacOSErrorSet mTolerateErrors;		// soft error conditions to ignore
	CFRef<CFArrayRef> mAllowOmissions;	// additionally allowed resource omissions
	
	// master validation state
	bool mValidated;					// core validation was attempted
	bool mRevocationChecked;			// the signature was checked for revocation
	OSStatus mValidationResult;			// outcome of core validation
	bool mValidationExpired;			// outcome had expired certificates
	
	// static executable validation state (nested within mValidated/mValid)
	bool mExecutableValidated;			// tried to validate executable file
	OSStatus mExecutableValidResult;		// outcome if mExecutableValidated

	// static resource validation state (nested within mValidated/mValid)
	bool mResourcesValidated;			// tried to validate resources
	bool mResourcesDeep;				// cached validation was deep
	OSStatus mResourcesValidResult;			// outcome if mResourceValidated or...
	ValidationContext *mResourcesValidContext; // resource error reporting funnel
	
	// validation progress state (set when static validation starts)
	SecCSFlags mValidationFlags;		// API flags passed to static validation
	unsigned mTotalWork;				// total expected work (arbitrary units)
	unsigned mCurrentWork;				// currently completed work
	bool mCancelPending;				// cancellation was requested
	Dispatch::Queue mProgressQueue;		// progress reporting queue

	// nested validation support
	const SecStaticCode *mOuterScope;	// containing code (if this is a nested validation; weak)
	ResourceBuilder *mResourceScope;	// current Resource validation stack (while validating; weak)

	// cached contents
	mutable CFRef<CFDataRef> mDir;		// code directory data
	mutable CodeDirectory::HashAlgorithms mHashAlgorithms; // available hash algorithms
	CFRef<CFDataRef> mSignature;		// CMS signature data
	CFAbsoluteTime mSigningTime;		// (signed) signing time
	CFAbsoluteTime mSigningTimestamp;		// Timestamp time (from timestamping authority)
	CFRef<CFDataRef> mCache[cdSlotCount]; // NULL => not tried, kCFNull => absent, other => present
	
	// alternative cache forms (storage may depend on cached contents above)
	CFRef<CFDictionaryRef> mInfoDict;	// derived from mCache slot
	CFRef<CFDictionaryRef> mEntitlements; // derived from mCache slot
	CFRef<CFDictionaryRef> mResourceDict; // derived from mCache slot
	const Requirement *mDesignatedReq;	// cached designated req if we made one up
	CFRef<CFDataRef> mCDHash;			// hash of chosen CodeDirectory
	CFRef<CFArrayRef> mCDHashes;		// hashes of all CodeDirectories (in digest type code order)
	CFRef<CFDictionaryRef> mCDHashFullDict;	// untruncated hashes of CodeDirectories (as dictionary)
	CEQueryContext_t mCEQueryContext; // Reference to the CoreEntitlements object associated with this Code's entitlements
	CFRef<CFDataRef> mCEReconstitutedEnts; // XML entitlements blob that has been reconsituted, used where the raw form IS NOT needed

	bool mGotResourceBase;				// asked mRep for resourceBasePath
	CFRef<CFURLRef> mResourceBase;		// URL form of resource base directory

	SecCodeCallback mMonitor;			// registered monitor callback

	LimitedAsync *mLimitedAsync;		// limited async workers for verification

	SecCSFlags mFlags;					// flags from creation
	bool mNotarizationChecked;			// ensure notarization check only performed once
	bool mStaplingChecked;				// ensure stapling check only performed once
	double mNotarizationDate;			// the notarization ticket's date, if online check failed
	bool mNetworkEnabledByDefault;		// whether this code object uses the network by default

	// signature verification outcome (mTrust == NULL => not done yet)
	CFRef<SecTrustRef> mTrust;			// outcome of crypto validation (valid or not)
	CFRef<CFArrayRef> mCertChain;
    bool mTrustedSigningCertChain;

	unsigned int mValidationCategory;
	CFRef<CFDictionaryRef> mDefaultDesignatedLWCR;
};


} // end namespace CodeSigning
} // end namespace Security

#endif // !_H_STATICCODE
