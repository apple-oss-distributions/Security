/*
 * Copyright (c) 2006-2012,2014 Apple Inc. All Rights Reserved.
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
// signer - Signing operation supervisor and controller
//
#ifndef _H_SIGNER
#define _H_SIGNER

#include "CodeSigner.h"
#include "cdbuilder.h"
#include "signerutils.h"
#include "StaticCode.h"
#include <security_utilities/utilities.h>

namespace Security {
namespace CodeSigning {


//
// The signer driver class.
// This is a workflow object, containing all the data needed for the various
// signing stages to cooperate. It is not meant to be API visible; that is
// SecCodeSigner's job.
//
class SecCodeSigner::Signer : public DiskRep::SigningContext {
public:
	Signer(SecCodeSigner &s, SecStaticCode *c) : state(s), code(c), requirements(NULL),
		useRemoteSigning(false), rsHandler(NULL), rsCertChain(NULL)
	{ strict = signingFlags() & kSecCSSignStrictPreflight; }
	~Signer() { ::free((Requirements *)requirements); }

	void sign(SecCSFlags flags);
	void remove(SecCSFlags flags);
	void edit(SecCSFlags flags);

	SecCodeSigner &state;
	SecStaticCode * const code;
	
	const CodeDirectory::HashAlgorithms& digestAlgorithms() const { return hashAlgorithms; }
	void setDigestAlgorithms(CodeDirectory::HashAlgorithms types) { hashAlgorithms = types; }
	
	std::string path() const { return cfStringRelease(rep->copyCanonicalPath()); }
	SecIdentityRef signingIdentity() const { return state.mSigner; }
	std::string signingIdentifier() const { return identifier; }
	CFArrayRef signingCertificateChain() const { return rsCertChain; }

	void setupRemoteSigning(CFArrayRef certChain, SecCodeRemoteSignHandler handler);

protected:
	void prepare(SecCSFlags flags);				// set up signing parameters
	void signMachO(Universal *fat, const Requirement::Context &context); // sign a Mach-O binary
	void signArchitectureAgnostic(const Requirement::Context &context); // sign anything else
	
	void prepareForEdit(SecCSFlags flags);		// set up signature editing
	void editMachO(Universal *fat); 			// edit a Mach-O binary
	void editArchitectureAgnostic(); 			// edit anything else

	// HashAlgorithm -> PreEncrypt hashes
	typedef std::map<CodeDirectory::HashAlgorithm, CFCopyRef<CFDataRef> >
		PreEncryptHashMap;
	// Architecture -> PreEncryptHashMap
	typedef std::map<Architecture, PreEncryptHashMap >
		PreEncryptHashMaps;
	// HashAlgorithm -> Hardened Runtime Version
	typedef std::map<CodeDirectory::HashAlgorithm, uint32_t>
		RuntimeVersionMap;
	// Architecture -> RuntimeVersionMap
	typedef std::map<Architecture, RuntimeVersionMap>
		RuntimeVersionMaps;
	// Architecture -> RawComponentMap
	typedef EditableDiskRep::RawComponentMap RawComponentMap;
	typedef std::map<Architecture, std::unique_ptr<RawComponentMap>>
		RawComponentMaps;

	void populate(DiskRep::Writer &writer);		// global
	void populate(CodeDirectory::Builder &builder, DiskRep::Writer &writer,
				  InternalRequirements &ireqs,
				  size_t offset, size_t length,
				  bool mainBinary, size_t execSegBase, size_t execSegLimit,
				  unsigned alternateDigestCount,
				  const PreEncryptHashMap& preEncryptHashMap,
				  uint32_t runtimeVersion, bool generateEntitlementDER);	// per-architecture
	CFDataRef signCodeDirectory(const CodeDirectory *cd,
								CFDictionaryRef hashDict, CFArrayRef hashList);

	uint32_t cdTextFlags(std::string text);		// convert text CodeDirectory flags
	std::string uniqueName() const;				// derive unique string from rep
	
protected:
	
	std::string sdkPath(const std::string &path) const;
	bool isAdhoc() const;
	SecCSFlags signingFlags() const;
	
private:
	static EditableDiskRep *editMainExecutableRep(DiskRep *rep);
	
	void addPreEncryptHashes(PreEncryptHashMap &map, SecStaticCode const *code);
	void addRuntimeVersions(RuntimeVersionMap &map, SecStaticCode const *code);
	
	void considerTeamID(const PreSigningContext& context);
	std::vector<Endian<uint32_t> > topSlots(CodeDirectory::Builder &builder) const;

	static bool booleanEntitlement(CFDictionaryRef entDict, CFStringRef key);
	static void cookEntitlements(CFDataRef entitlements, bool generateDER,
								 uint64_t *execSegFlags, CFDataRef *entitlementsDER);

	CFDataRef signCodeDirectoryWithIdentity(const CodeDirectory *cd,
											CFDictionaryRef hashDict, CFArrayRef hashList);
	CFDataRef signCodeDirectoryRemote(const CodeDirectory *cd,
									  CFDictionaryRef hashDict, CFArrayRef hashList);

protected:
	void buildResources(std::string root, std::string relBase, CFDictionaryRef rules);
	CFMutableDictionaryRef signNested(const std::string &path, const std::string &relpath);
	CFDataRef hashFile(const char *path, CodeDirectory::HashAlgorithm type);
	CFDictionaryRef hashFile(const char *path, CodeDirectory::HashAlgorithms types);
	
private:
	RefPointer<DiskRep> rep;		// DiskRep of Code being signed
	CFRef<CFDictionaryRef> resourceDirectory;	// resource directory
	CFRef<CFDataRef> resourceDictData; // XML form of resourceDirectory
	CodeDirectory::HashAlgorithms hashAlgorithms; // hash algorithm(s) to use
	std::string identifier;			// signing identifier
	std::string teamID;             // team identifier
	CFRef<CFDataRef> entitlements;	// entitlements
	vector<CFRef<CFDataRef>> launchConstraints; // Array of Lightweight Code Requirements
	CFRef<CFDataRef> libraryConstraints; // Lightweight Code Requirement for library load restrictions
	Architecture preEncryptMainArch; // pre-encrypt main architecture
	PreEncryptHashMaps preEncryptHashMaps;  // pre-encrypt hashes to keep
	Architecture runtimeVersionMainArch; // runtime version main architecture
	RuntimeVersionMaps runtimeVersionMap; // runtime versions to keep
	uint32_t cdFlags;				// CodeDirectory flags
	const Requirements *requirements; // internal requirements ready-to-use
	size_t pagesize;				// size of main executable pages
	CFAbsoluteTime signingTime;		// signing time for CMS signature (0 => now)
	bool emitSigningTime;			// emit signing time as a signed CMS attribute
	bool strict;					// strict validation

	// Remote signing data.
	bool useRemoteSigning;
	SecCodeRemoteSignHandler rsHandler;
	CFRef<CFArrayRef> rsCertChain;

	// Signature Editing
	Architecture editMainArch;		// main architecture for editing
	RawComponentMaps editComponents; // components for signature
	
private:
	Mutex resourceLock;
};


} // end namespace CodeSigning
} // end namespace Security

#endif // !_H_CODESIGNER
