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
// bundlediskrep - bundle directory disk representation
//
#ifndef _H_BUNDLEDISKREP
#define _H_BUNDLEDISKREP

#include "diskrep.h"
#include "machorep.h"

#include <sys/cdefs.h>

#if TARGET_OS_OSX
__BEGIN_DECLS
#include <AppleFSCompression/AppleFSCompression.h>
__END_DECLS
#endif

namespace Security {
namespace CodeSigning {


#define BUNDLEDISKREP_DIRECTORY		"_CodeSignature"
#define CODERESOURCES_LINK			"CodeResources"
#define STORE_RECEIPT_DIRECTORY		"_MASReceipt"


//
// A BundleDiskRep represents a standard Mac OS X bundle on disk.
// The bundle is expected to have an Info.plist, and a "main executable file"
// of some sort (as indicated therein).
// The BundleDiskRep stores the necessary components in the main executable
// if it is in Mach-O format, or in files in a _CodeSignature directory if not.
// This DiskRep supports resource sealing.
//
class BundleDiskRep : public DiskRep, public EditableDiskRep {
public:
	BundleDiskRep(const char *path, const Context *ctx = NULL);
	BundleDiskRep(CFBundleRef ref, const Context *ctx = NULL);
	~BundleDiskRep();
	
	CFDataRef component(CodeDirectory::SpecialSlot slot);
	RawComponentMap createRawComponents();
	CFDataRef identification();
	DiskRep *mainExecRep() const { return mExecRep.get(); };
	std::string mainExecutablePath();
	CFURLRef copyCanonicalPath();
	std::string resourcesRootPath();
	std::string resourcesRelativePath();
	void adjustResources(ResourceBuilder &builder);
	Universal *mainExecutableImage();
	void prepareForSigning(SigningContext &context);
	size_t signingBase();
	size_t signingLimit();
	size_t execSegBase(const Architecture *arch);
	size_t execSegLimit(const Architecture *arch);
	std::string format();
	CFArrayRef modifiedFiles();
	UnixPlusPlus::FileDesc &fd();
	void flush();
    CFDictionaryRef copyDiskRepInformation();

	std::string recommendedIdentifier(const SigningContext &ctx);
	std::string explicitIdentifier();
	CFDictionaryRef defaultResourceRules(const SigningContext &ctx);
	const Requirements *defaultRequirements(const Architecture *arch, const SigningContext &ctx);
	size_t pageSize(const SigningContext &ctx);

	void strictValidate(const CodeDirectory* cd, const ToleratedErrors& tolerated, SecCSFlags flags);
	void strictValidateStructure(const CodeDirectory* cd, const ToleratedErrors& tolerated, SecCSFlags flags);
	CFArrayRef allowedResourceOmissions();

	void registerStapledTicket();
	CFDataRef copyStapledTicket();

	bool appleInternalForcePlatform() const {return forcePlatform;};

	CFBundleRef bundle() const { return mBundle; }

public:
	Writer *writer();
	class Writer;
	friend class Writer;
	
protected:
	std::string metaPath(const char *name);
	void createMeta();						// (try to) create the meta-file directory
	CFDataRef metaData(const char *name);
	CFDataRef metaData(CodeDirectory::SpecialSlot slot);
	
private:
	void setup(const Context *ctx);			// shared init
	void checkModifiedFile(CFMutableArrayRef files, CodeDirectory::SpecialSlot slot);
	CFDataRef loadRegularFile(CFURLRef url);
	void recordStrictError(OSStatus error);
	void validateMetaDirectory(const CodeDirectory* cd, SecCSFlags flags);
	void validateFrameworkRoot(std::string root);
	void checkPlainFile(UnixPlusPlus::FileDesc fd, const std::string& path);
	void checkMoved(CFURLRef oldPath, CFURLRef newPath);
	void componentFromExec(bool fromExec);

private:
	CFRef<CFBundleRef> mBundle;
	std::string mMetaPath;					// path to directory containing signing files
	bool mMetaExists;						// separate meta-file directory exists
	CFRef<CFURLRef> mMainExecutableURL;		// chosen main executable URL
	bool mInstallerPackage;					// is an installer (not executable) bundle
	bool mAppLike;							// is some form of app
	string mFormat;							// format description string
	RefPointer<DiskRep> mExecRep;			// DiskRep for main executable file
	bool mComponentsFromExec;				// components are drawn from main executable diskrep
	bool mComponentsFromExecValid;			// mComponentsFromExec is valid (tri-state)
	std::set<CodeDirectory::SpecialSlot> mUsedComponents; // remember what components we've retrieved
	std::set<OSStatus> mStrictErrors;		// strict validation errors encountered
	bool forcePlatform;						// treat as anchor apple on apple internal
};


//
// Writers
//
//
class BundleDiskRep::Writer : public DiskRep::Writer {
	friend class BundleDiskRep;
public:
	Writer(BundleDiskRep *r);
	
	void component(CodeDirectory::SpecialSlot slot, CFDataRef data);
	void remove();
	void flush();
	
protected:
	DiskRep *execRep() { return rep->mExecRep; }
	void remove(CodeDirectory::SpecialSlot slot);
	void purgeMetaDirectory();

protected:
	RefPointer<BundleDiskRep> rep;
	RefPointer<DiskRep::Writer> execWriter;
	bool mMadeMetaDirectory;
	std::set<std::string> mWrittenFiles;
};


} // end namespace CodeSigning
} // end namespace Security

#endif // !_H_BUNDLEDISKREP
