/*
 * Copyright (c) 2006-2021 Apple Inc. All Rights Reserved.
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
#include "resources.h"
#include "csutilities.h"
#include "cserror.h"
#include <security_utilities/unix++.h>
#include <security_utilities/debugging.h>
#include <Security/CSCommon.h>
#include <security_utilities/unix++.h>
#include <security_utilities/cfmunge.h>

// These are pretty nasty, but are a quick safe fix
// to pass information down to the gatekeeper collection tool
extern "C" {
	int GKBIS_DS_Store_Present;
	int GKBIS_Dot_underbar_Present;
	int GKBIS_Num_localizations;
	int GKBIS_Num_files;
	int GKBIS_Num_dirs;
	int GKBIS_Num_symlinks;
}

namespace Security {
namespace CodeSigning {


static string removeTrailingSlash(string path)
{
	if (path.substr(path.length()-2, 2) == "/.") {
		return path.substr(0, path.length()-2);
	} else if (path.substr(path.length()-1, 1) == "/") {
		return path.substr(0, path.length()-1);
	} else {
		return path;
	}
}

//
// Construction and maintainance
//
ResourceBuilder::ResourceBuilder(const std::string &root, const std::string &relBase,
								 CFDictionaryRef rulesDict, bool strict, const MacOSErrorSet& toleratedErrors)
								 : mCheckUnreadable(strict && toleratedErrors.find(errSecCSSignatureNotVerifiable) == toleratedErrors.end()),
								   mCheckUnknownType(strict && toleratedErrors.find(errSecCSResourceNotSupported) == toleratedErrors.end())
{
	assert(!root.empty());
	char realroot[PATH_MAX];
	if (realpath(root.c_str(), realroot) == NULL) {
		UnixError::throwMe();
	}
	mRoot = realroot;
	if (realpath(removeTrailingSlash(relBase).c_str(), realroot) == NULL) {
		UnixError::throwMe();
	}
	mRelBase = realroot;
	if (mRoot != mRelBase && mRelBase != mRoot + "/Contents") {
		MacOSError::throwMe(errSecCSBadBundleFormat);
	}
	const char * paths[2] = { mRoot.c_str(), NULL };
	mFTS = fts_open((char * const *)paths, FTS_PHYSICAL | FTS_COMFOLLOW | FTS_NOCHDIR, NULL);
	if (!mFTS) {
		UnixError::throwMe();
	}
	mRawRules = rulesDict;
	CFDictionary rules(rulesDict, errSecCSResourceRulesInvalid);
	rules.apply(this, &ResourceBuilder::addRule);
}

ResourceBuilder::~ResourceBuilder()
{
	for (Rules::iterator it = mRules.begin(); it != mRules.end(); ++it) {
		delete *it;
	}
	fts_close(mFTS);	// do not check error - it's not worth aborting over (double fault etc.)
}


//
// Parse and add one matching rule
//
void ResourceBuilder::addRule(CFTypeRef key, CFTypeRef value)
{
	string pattern = cfString(key, errSecCSResourceRulesInvalid);
	unsigned weight = 1;
	uint32_t flags = 0;
	if (CFGetTypeID(value) == CFBooleanGetTypeID()) {
		if (value == kCFBooleanFalse) {
			flags |= omitted;
		}
	} else {
		CFDictionary rule(value, errSecCSResourceRulesInvalid);
		if (CFNumberRef weightRef = rule.get<CFNumberRef>("weight")) {
			weight = cfNumber<unsigned int>(weightRef);
		}
		if (CFBooleanRef omitRef = rule.get<CFBooleanRef>("omit")) {
			if (omitRef == kCFBooleanTrue) {
				flags |= omitted;
			}
		}
		if (CFBooleanRef optRef = rule.get<CFBooleanRef>("optional")) {
			if (optRef == kCFBooleanTrue) {
				flags |= optional;
			}
		}
		if (CFBooleanRef nestRef = rule.get<CFBooleanRef>("nested")) {
			if (nestRef == kCFBooleanTrue) {
				flags |= nested;
			}
		}
	}
	// All rules coming in through addRule come from the user supplied data, so make that clear.
	flags |= user_controlled;
	addRule(new Rule(pattern, weight, flags));
}

static bool findStringEndingNoCase(const char *path, const char * end)
{
	size_t len_path = strlen(path);
	size_t len_end = strlen(end);

	if (len_path >= len_end) {
		return strcasecmp(path + (len_path - len_end), end) == 0;
	} else {
		return false;
	}
}

void ResourceBuilder::scan(Scanner next)
{
	scan(next, nil);
}

//
// Locate the next non-ignored file, look up its rule, and return it.
// If the unhandledScanner is passed, call it with items the original scan may
// have chosen to skip.
// Returns NULL when we're out of files.
//
void ResourceBuilder::scan(Scanner next, Scanner unhandledScanner)
{
	bool first = true;

	// The FTS scan needs to visit skipped regions if the caller is requesting callbacks
	// for anything unhandled. In that case, don't skip the entries in FTS but instead
	// keep track of entry and exit locally.
	bool visitSkippedDirectories = (unhandledScanner != NULL);
	bool isSkippingDirectory = false;
	string skippingDirectoryRoot;

	while (FTSENT *ent = fts_read(mFTS)) {
		static const char ds_store[] = ".DS_Store";
		const char *relpath = ent->fts_path + mRoot.size(); // skip prefix
		bool wasScanned = false;
		Rule *rule = NULL;

		if (strlen(relpath) > 0) {
			relpath += 1;	// skip "/"
		}

		std::string rp;
		if (mRelBase != mRoot) {
			assert(mRelBase == mRoot + "/Contents");
			rp = "../" + string(relpath);
			if (rp.substr(0, 12) == "../Contents/") {
				rp = rp.substr(12);
			}
			relpath = rp.c_str();
		}
		switch (ent->fts_info) {
			case FTS_F:
				secinfo("rdirenum", "file %s", ent->fts_path);
				GKBIS_Num_files++;

				// These are checks for the gatekeeper collection
				static const char underbar[] = "._";
				if (strncasecmp(ent->fts_name, underbar, strlen(underbar)) == 0) {
					GKBIS_Dot_underbar_Present++;
				}

				if (strcasecmp(ent->fts_name, ds_store) == 0) {
					GKBIS_DS_Store_Present++;
				}

				rule = findRule(relpath);
				if (rule && !isSkippingDirectory) {
					if (!(rule->flags & (omitted | exclusion))) {
						wasScanned = true;
						next(ent, rule->flags, string(relpath), rule);
					}
				}

				if (unhandledScanner && !wasScanned) {
					unhandledScanner(ent, rule ? rule->flags : 0, string(relpath), rule);
				}

				break;
			case FTS_SL:
				// symlinks cannot ever be nested code, so quietly convert to resource file
				secinfo("rdirenum", "symlink %s", ent->fts_path);
				GKBIS_Num_symlinks++;

				if (strcasecmp(ent->fts_name, ds_store) == 0) {
					MacOSError::throwMe(errSecCSDSStoreSymlink);
				}

				rule = findRule(relpath);
				if (rule && !isSkippingDirectory) {
					if (!(rule->flags & (omitted | exclusion))) {
						wasScanned = true;
						next(ent, rule->flags & ~nested, string(relpath), rule);
					}
				}

				if (unhandledScanner && !wasScanned) {
					unhandledScanner(ent, rule ? rule->flags : 0, string(relpath), rule);
				}

				break;
			case FTS_D:
				secinfo("rdirenum", "entering %s", ent->fts_path);
				GKBIS_Num_dirs++;

				// Directories don't need to worry about calling the unhandled scanner directly because
				// we'll always traverse deeply to visit anything inside, even if it was inside
				// an exlusion rule.

				if (!first && !isSkippingDirectory) {	// skip root directory or anything we're skipping
					rule = findRule(relpath);
					if (rule) {
						if (rule->flags & nested) {
							if (strchr(ent->fts_name, '.')) {	// nested, has extension -> treat as nested bundle
								next(ent, rule->flags, string(relpath), rule);
								fts_set(mFTS, ent, FTS_SKIP);
							}
						} else if (rule->flags & exclusion) {	// exclude the whole directory
							if (visitSkippedDirectories) {
								isSkippingDirectory = true;
								skippingDirectoryRoot = relpath;
								secinfo("rdirenum", "entering excluded path: %s", skippingDirectoryRoot.c_str());
							} else {
								fts_set(mFTS, ent, FTS_SKIP);
							}
						}
					}
				}

				// Report the number of localizations
				if (findStringEndingNoCase(ent->fts_name, ".lproj")) {
					GKBIS_Num_localizations++;
				}
				first = false;
				break;
			case FTS_DP:
				secinfo("rdirenum", "leaving %s", ent->fts_path);
				if (isSkippingDirectory && skippingDirectoryRoot == relpath) {
					secinfo("rdirenum", "exiting excluded path: %s", skippingDirectoryRoot.c_str());
					isSkippingDirectory = false;
					skippingDirectoryRoot.clear();
				}
				break;
			case FTS_DNR:
				secinfo("rdirenum", "cannot read directory %s", ent->fts_path);
				if (mCheckUnreadable) {
					MacOSError::throwMe(errSecCSSignatureNotVerifiable);
				}
				break;
			default:
				secinfo("rdirenum", "type %d (errno %d): %s", ent->fts_info, ent->fts_errno, ent->fts_path);
				if (mCheckUnknownType) {
					MacOSError::throwMe(errSecCSResourceNotSupported);
				}
				break;
		}
	}
}


//
// Check a single for for inclusion in the resource envelope
//
bool ResourceBuilder::includes(string path) const
{
	// process first-directory exclusions
	size_t firstslash = path.find('/');
	if (firstslash != string::npos) {
		if (Rule *rule = findRule(path.substr(0, firstslash))) {
			if (rule->flags & exclusion) {
				return rule->flags & softTarget;
			}
		}
	}
	
	// process full match
	if (Rule *rule = findRule(path)) {
		return !(rule->flags & (omitted | exclusion)) || (rule->flags & softTarget);
	} else {
		return false;
	}
}


//
// Find the best-matching resource rule for an alleged resource file.
// Returns NULL if no rule matches, or an exclusion rule applies.
//
ResourceBuilder::Rule *ResourceBuilder::findRule(string path) const
{
	Rule *bestRule = NULL;
	secinfo("rscan", "test %s", path.c_str());
	for (Rules::const_iterator it = mRules.begin(); it != mRules.end(); ++it) {
		Rule *rule = *it;
		secinfo("rscan", "try %s", rule->source.c_str());
		if (rule->match(path.c_str())) {
			secinfo("rscan", "match");
			if (rule->flags & exclusion) {
				secinfo("rscan", "excluded");
				return rule;
			}
			if (!bestRule || rule->weight > bestRule->weight) {
				bestRule = rule;
			}

#if TARGET_OS_WATCH
			/* rdar://problem/30517969 */
			if (bestRule && bestRule->weight == rule->weight && !(bestRule->flags & omitted) && (rule->flags & omitted)) {
				bestRule = rule;
			}
#endif
		}
	}
	secinfo("rscan", "choosing %s (%d,0x%x)",
			bestRule ? bestRule->source.c_str() : "NOTHING",
			bestRule ? bestRule->weight : 0,
			bestRule ? bestRule->flags : 0);
	return bestRule;
}


//
// Hash a file and return a CFDataRef with the hash
//
CFDataRef ResourceBuilder::hashFile(const char *path, CodeDirectory::HashAlgorithm type)
{
	UnixPlusPlus::AutoFileDesc fd(path);
	fd.fcntl(F_NOCACHE, true);		// turn off page caching (one-pass)
	RefPointer<DynamicHash> hasher(CodeDirectory::hashFor(type));
	hashFileData(fd, hasher.get());
	vector<Hashing::Byte> digest_vector(hasher->digestLength());
	hasher->finish(digest_vector.data());
	return CFDataCreate(NULL, digest_vector.data(), digest_vector.size() * sizeof(Hashing::Byte));
}


//
// Hash a file to multiple hash types and return a dictionary suitable to form a resource seal
//
CFMutableDictionaryRef ResourceBuilder::hashFile(const char *path, CodeDirectory::HashAlgorithms types, bool strictCheck)
{
	UnixPlusPlus::AutoFileDesc fd(path);
	fd.fcntl(F_NOCACHE, true);		// turn off page caching (one-pass)
	if (strictCheck) {
		if (fd.hasExtendedAttribute(XATTR_RESOURCEFORK_NAME)) {
			CFStringRef message = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("Disallowed xattr %s found on %s"), XATTR_RESOURCEFORK_NAME, path);
			CSError::throwMe(errSecCSInvalidAssociatedFileData, kSecCFErrorResourceSideband, message);
		}
		if (fd.hasExtendedAttribute(XATTR_FINDERINFO_NAME)) {
			CFStringRef message = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("Disallowed xattr %s found on %s"), XATTR_FINDERINFO_NAME, path);
			CSError::throwMe(errSecCSInvalidAssociatedFileData, kSecCFErrorResourceSideband, message);
		}
	}
	CFRef<CFMutableDictionaryRef> result = makeCFMutableDictionary();
	CFMutableDictionaryRef resultRef = result;
	CodeDirectory::multipleHashFileData(fd, 0, types, ^(CodeDirectory::HashAlgorithm type, Security::DynamicHash *hasher) {
		size_t length = hasher->digestLength();
		vector<Hashing::Byte> digest_vector(length);
		hasher->finish(digest_vector.data());
		CFDictionaryAddValue(resultRef, CFTempString(hashName(type)), CFTempData(digest_vector.data(), length));
	});
	return result.yield();
}


std::string ResourceBuilder::hashName(CodeDirectory::HashAlgorithm type)
{
	switch (type) {
		case kSecCodeSignatureHashSHA1:
			return "hash";
		default:
			char name[20];
			snprintf(name, sizeof(name), "hash%d", int(type));
			return name;
	}
}


//
// Regex matching objects
//
ResourceBuilder::Rule::Rule(const std::string &pattern, unsigned w, uint32_t f)
	: weight(w), flags(f), source(pattern)
{
	if (::regcomp(this, pattern.c_str(), REG_EXTENDED | REG_NOSUB)) {	//@@@ REG_ICASE?
		MacOSError::throwMe(errSecCSResourceRulesInvalid);
	}
	secinfo("csresource", "%p rule %s added (weight %d, flags 0x%x)", this, pattern.c_str(), w, f);
}

ResourceBuilder::Rule::~Rule()
{
	::regfree(this);
}

bool ResourceBuilder::Rule::match(const char *s) const
{
	switch (::regexec(this, s, 0, NULL, 0)) {
		case 0:
			return true;
		case REG_NOMATCH:
			return false;
		default:
			MacOSError::throwMe(errSecCSResourceRulesInvalid);
	}
}


std::string ResourceBuilder::escapeRE(const std::string &s)
{
	string r;
	for (string::const_iterator it = s.begin(); it != s.end(); ++it) {
		char c = *it;
		if (strchr("\\[]{}().+*?^$|", c)) {
			r.push_back('\\');
		}
		r.push_back(c);
	}
	return r;
}


//
// Resource Seals
//
ResourceSeal::ResourceSeal(CFTypeRef it)
	: mDict(NULL), mRequirement(NULL), mLink(NULL), mFlags(0)
{
	if (it == NULL) {
		MacOSError::throwMe(errSecCSResourcesInvalid);
	}
	if (CFGetTypeID(it) == CFDataGetTypeID()) {	// old-style form with just a hash
		mDict.take(cfmake<CFDictionaryRef>("{hash=%O}", it));
	} else if (CFGetTypeID(it) == CFDictionaryGetTypeID()) {
		mDict = CFDictionaryRef(it);
	} else {
		MacOSError::throwMe(errSecCSResourcesInvalid);
	}

	int optional = 0;
	bool err;
	if (CFDictionaryGetValue(mDict, CFSTR("requirement"))) {
		err = !cfscan(mDict, "{requirement=%SO,?optional=%B}", &mRequirement, &optional);
	} else if (CFDictionaryGetValue(mDict, CFSTR("symlink"))) {
		err = !cfscan(mDict, "{symlink=%SO,?optional=%B}", &mLink, &optional);
	} else {
		err = !cfscan(mDict, "{?optional=%B}", &optional);
	}

	if (err) {
		MacOSError::throwMe(errSecCSResourcesInvalid);
	}
	if (optional) {
		mFlags |= ResourceBuilder::optional;
	}
	if (mRequirement) {
		mFlags |= ResourceBuilder::nested;
	}
}


const Hashing::Byte *ResourceSeal::hash(CodeDirectory::HashAlgorithm type) const
{
	std::string name = ResourceBuilder::hashName(type);
	CFTypeRef hash = CFDictionaryGetValue(mDict, CFTempString(name));
	if (hash == NULL) {	// pre-agility fallback
		hash = CFDictionaryGetValue(mDict, CFSTR("hash"));
	}
	if (hash == NULL || CFGetTypeID(hash) != CFDataGetTypeID()) {
		MacOSError::throwMe(errSecCSResourcesInvalid);
	}
	return CFDataGetBytePtr(CFDataRef(hash));
}


} // end namespace CodeSigning
} // end namespace Security
