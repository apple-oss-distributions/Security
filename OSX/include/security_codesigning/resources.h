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
// resource directory construction and verification
//
#ifndef _H_RSIGN
#define _H_RSIGN

#include "codedirectory.h"
#include <security_utilities/utilities.h>
#include <security_utilities/cfutilities.h>
#include <security_utilities/hashing.h>
#include "regex.h"
#include <CoreFoundation/CoreFoundation.h>
#include <vector>
#include <fts.h>

namespace Security {
namespace CodeSigning {


//
// The builder of ResourceDirectories.
//
// Note that this *is* a ResourceEnumerator, which can enumerate
// its source directory once (only).
//
class ResourceBuilder {
	NOCOPY(ResourceBuilder)
public:
	ResourceBuilder(const std::string &root, const std::string &relBase,
		CFDictionaryRef rulesDict, bool strict, const MacOSErrorSet& toleratedErrors);
	~ResourceBuilder();

	std::string root() const { return mRoot; }
	
	enum {
		optional = 0x01,				// may be absent at runtime
		omitted = 0x02,					// do not seal even if present
		nested = 0x04,					// nested code (recursively signed)
		exclusion = 0x10,				// overriding exclusion (stop looking)
		softTarget = 0x20,				// valid symlink target even though omitted/excluded
		user_controlled = 0x40,			// whether the rule was read from a user controlled file
	};
	
	typedef unsigned int Weight;
	
public:
	class Rule : private regex_t {
	public:
		Rule(const std::string &pattern, Weight weight, uint32_t flags);
		~Rule();
		
		bool match(const char *s) const;
		
		const Weight weight;
		const uint32_t flags;
		std::string source;
	};
	void addRule(Rule *rule) { mRules.push_back(rule); }
	void addExclusion(const std::string &pattern, uint32_t flags = 0) { mRules.insert(mRules.begin(), new Rule(pattern, 0, exclusion | flags)); }

	static std::string escapeRE(const std::string &s);
	
	typedef void (^Scanner)(FTSENT *ent, uint32_t flags, const std::string relpath, Rule *rule);
	void scan(Scanner next);
	void scan(Scanner next, Scanner unhandled);
	bool includes(string path) const;
	Rule *findRule(string path) const;

	static CFDataRef hashFile(const char *path, CodeDirectory::HashAlgorithm type);
	static CFMutableDictionaryRef hashFile(const char *path, CodeDirectory::HashAlgorithms types, bool strictCheck);
	
	static std::string hashName(CodeDirectory::HashAlgorithm type);
	
	CFDictionaryRef rules() const { return mRawRules; }

protected:
	void addRule(CFTypeRef key, CFTypeRef value);
	
private:
	std::string mRoot, mRelBase;
	FTS *mFTS;
	CFCopyRef<CFDictionaryRef> mRawRules;
	typedef std::vector<Rule *> Rules;
	Rules mRules;
	bool mCheckUnreadable;
	bool mCheckUnknownType;
};


//
// The "seal" on a single resource.
//
class ResourceSeal {
	NOCOPY(ResourceSeal)
public:
	ResourceSeal(CFTypeRef ref);

public:
	const Hashing::Byte *hash(CodeDirectory::HashAlgorithm type) const;
	bool nested() const { return mFlags & ResourceBuilder::nested; }
	bool optional() const { return mFlags & ResourceBuilder::optional; }
	CFDictionaryRef dict() const { return mDict; }
	CFStringRef requirement() const { return mRequirement; }
	CFStringRef link() const { return mLink; }

private:
	CFRef<CFDictionaryRef> mDict;
	CFStringRef mRequirement;
	CFStringRef mLink;
	uint32_t mFlags;
};


} // end namespace CodeSigning
} // end namespace Security

#endif // !_H_RSIGN
