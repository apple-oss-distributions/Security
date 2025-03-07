/*
 * Copyright (c) 2014 Apple Inc. All Rights Reserved.
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

#include <dirent.h>
#include <unistd.h>
#include <security_utilities/cfutilities.h>
#include <security_utilities/debugging.h>
#include <security_utilities/logging.h>
#include "dirscanner.h"
#include "csutilities.h"

#include <sstream>

namespace Security {
namespace CodeSigning {


DirScanner::DirScanner(const char *path)
	: init(false)
{
	this->path = std::string(path);
	this->initialize();
}

DirScanner::DirScanner(string path)
	: init(false)
{
	this->path = path;
	this->initialize();
}

DirScanner::~DirScanner()
{
        if (this->dp != NULL)
                (void) closedir(this->dp);
}

void DirScanner::initialize()
{
	if (this->dp == NULL) {
		errno = 0;
		if ((this->dp = opendir(this->path.c_str())) == NULL) {
			if (errno == ENOENT) {
				init = false;
			} else {
				UnixError::check(-1);
			}
		} else
			init = true;
	} else
		MacOSError::throwMe(errSecInternalError);
}

struct dirent * DirScanner::getNext()
{
	struct dirent* ent;
	do {
		int rc = readdir_r(this->dp, &this->entBuffer, &ent);
		if (rc)
			UnixError::throwMe(rc);
	} while (ent && (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0));
	return ent;
}

bool DirScanner::initialized()
{
	return this->init;
}
	
void DirScanner::unlink(const struct dirent* ent, int flags)
{
	UnixError::check(::unlinkat(dirfd(this->dp), ent->d_name, flags));
}

bool DirScanner::isRegularFile(dirent* dp)
{
	switch (dp->d_type) {
	case DT_REG:
		return true;
	default:
		return false;
	case DT_UNKNOWN:
		{
			struct stat st;
			MacOSError::check(::stat((this->path + "/" + dp->d_name).c_str(), &st));
			return S_ISREG(st.st_mode);
		}
	}
}



DirValidator::~DirValidator()
{
	for (Rules::iterator it = mRules.begin(); it != mRules.end(); ++it)
		delete *it;
}

void DirValidator::validate(const string &root, OSStatus error)
{
	std::set<Rule *> reqMatched;
	FTS fts(root);
	while (FTSENT *ent = fts_read(fts)) {
		const char *relpath = ent->fts_path + root.size() + 1;	// skip prefix + "/"
		bool executable = ent->fts_statp->st_mode & (S_IXUSR | S_IXGRP | S_IXOTH);
		Rule *rule = NULL;
		switch (ent->fts_info) {
		case FTS_F:
			secinfo("dirval", "file %s", ent->fts_path);
			rule = match(relpath, file, executable);
			break;
		case FTS_SL: {
			secinfo("dirval", "symlink %s", ent->fts_path);
			char target[PATH_MAX];
			ssize_t len = ::readlink(ent->fts_accpath, target, sizeof(target)-1);
			if (len < 0)
				UnixError::throwMe();
			target[len] = '\0';
			rule = match(relpath, symlink, executable, target);
			break;
		}
		case FTS_D:
			secinfo("dirval", "entering %s", ent->fts_path);
			if (ent->fts_level == FTS_ROOTLEVEL)
				continue;	// skip root directory
			rule = match(relpath, directory, executable);
			if (!rule || !(rule->flags & descend))
				fts_set(fts, ent, FTS_SKIP);	// do not descend
			break;
		case FTS_DP:
			secinfo("dirval", "leaving %s", ent->fts_path);
			continue;
		default:
			secinfo("dirval", "type %d (errno %d): %s", ent->fts_info, ent->fts_errno, ent->fts_path);
			MacOSError::throwMe(error);	 // not a file, symlink, or directory
		}
		if (!rule) {
			bool skip = false;
			if (ent->fts_info == FTS_F &&
				pathFileSystemUsesXattrFiles(root.c_str()) &&
				pathIsValidXattrFile(std::string(ent->fts_path))) {
				// If the file is on a volume that uses xattr files, and this path is a valid xattr file
				// then its ok to skip over it without matching anything expected.
				secinfo("dirval", "skipping file due to xattr: %s", ent->fts_path);
				skip = true;
			}
			if (!skip) {
				MacOSError::throwMe(error);	 // no match
			}
		}
		else if (rule->flags & required) {
			reqMatched.insert(rule);
		}
	}
	if (reqMatched.size() != (unsigned long) mRequireCount) {
		ostringstream os;
		os << "matched " << reqMatched.size() << " of " << mRequireCount << " required rules";
		secinfo("dirval", "%s", os.str().c_str());
		MacOSError::throwMe(error);		 // not all required rules were matched
	}
}

DirValidator::Rule * DirValidator::match(const char *path, uint32_t flags, bool executable, const char *target)
{
	for (Rules::iterator it = mRules.begin(); it != mRules.end(); ++it) {
		Rule *rule = *it;
		if ((rule->flags & flags)
		    && !(executable && (rule->flags & noexec))
		    && rule->match(path)
		    && (!target || rule->matchTarget(path, target)))
			return rule;
	}
	return NULL;
}

DirValidator::FTS::FTS(const string &path, int options)
{
	const char * paths[2] = { path.c_str(), NULL };
	mFTS = fts_open((char * const *)paths, options, NULL);
	if (!mFTS)
		UnixError::throwMe();
}

DirValidator::FTS::~FTS()
{
	fts_close(mFTS);
}

DirValidator::Rule::Rule(const string &pattern, uint32_t flags, TargetPatternBuilder targetBlock)
	: ResourceBuilder::Rule(pattern, 0, flags), mTargetBlock(NULL)
{
	if (targetBlock)
		mTargetBlock = Block_copy(targetBlock);
}

DirValidator::Rule::~Rule()
{
	if (mTargetBlock)
		Block_release(mTargetBlock);
}

bool DirValidator::Rule::matchTarget(const char *path, const char *target) const
{
    if (!mTargetBlock) {
        Syslog::notice("code signing internal problem: !mTargetBlock");
		MacOSError::throwMe(errSecCSInternalError);
    }
	string pattern = mTargetBlock(path, target);
	if (pattern.empty())
		return true;	// always match empty pattern
	secinfo("dirval", "%s: match target %s against %s", path, target, pattern.c_str());
	regex_t re;
    if (::regcomp(&re, pattern.c_str(), REG_EXTENDED | REG_NOSUB)) {
        Syslog::notice("code signing internal problem: failed to compile internal RE");
		MacOSError::throwMe(errSecCSInternalError);
    }
    int rv = ::regexec(&re, target, 0, NULL, 0);
	::regfree(&re);
	switch (rv) {
	case 0:
		return true;
	case REG_NOMATCH:
		return false;
	default:
        Syslog::notice("code signing internal error: regexec failed error=%d", rv);
		MacOSError::throwMe(errSecCSInternalError);
	}
}


} // end namespace CodeSigning
} // end namespace Security
