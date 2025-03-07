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
// cdbuilder - constructor for CodeDirectories
//
#include "cdbuilder.h"
#include <security_utilities/memutils.h>
#include <cmath>

using namespace UnixPlusPlus;
using LowLevelMemoryUtilities::alignUp;


namespace Security {
namespace CodeSigning {


//
// Create an (empty) builder
//
CodeDirectory::Builder::Builder(HashAlgorithm digestAlgorithm)
	: mFlags(0),
	  mHashType(digestAlgorithm),
	  mPlatform(0),
	  mSpecialSlots(0),
	  mCodeSlots(0),
	  mScatter(NULL),
	  mScatterSize(0),
	  mExecSegOffset(0),
	  mExecSegLimit(0),
	  mExecSegFlags(0),
	  mGeneratePreEncryptHashes(false),
	  mRuntimeVersion(0),
	  mDir(NULL)
{
	mDigestLength = (uint32_t)MakeHash<Builder>(this)->digestLength();
	mSpecial = (unsigned char *)calloc(cdSlotMax, mDigestLength);
}

CodeDirectory::Builder::~Builder()
{
	::free(mSpecial);
	::free(mScatter);
}


//
// Set the source of the main executable (i.e. the code pages)
//
void CodeDirectory::Builder::executable(string path,
	size_t pagesize, size_t offset, size_t length)
{
	mExec.close();			// any previously opened one
	mExec.open(path);
	mPageSize = pagesize;
	mExecOffset = offset;
	mExecLength = length;
}

void CodeDirectory::Builder::reopen(string path, size_t offset, size_t length)
{
	assert(opened());					// already called executable()
	mExec.close();
	mExec.open(path);
	mExecOffset = offset;
	mExecLength = length;
}

bool CodeDirectory::Builder::opened()
{
	return bool(mExec);
}


//
// Set the source for one special slot
//
void CodeDirectory::Builder::specialSlot(SpecialSlot slot, CFDataRef data)
{
	assert(slot <= cdSlotMax);
	MakeHash<Builder> hash(this);
	hash->update(CFDataGetBytePtr(data), CFDataGetLength(data));
	hash->finish(specialSlot(slot));
	mFilledSpecialSlots.insert(slot);
	if (slot >= mSpecialSlots)
		mSpecialSlots = slot;
}


//
// Allocate a Scatter vector
//
CodeDirectory::Scatter *CodeDirectory::Builder::scatter(unsigned count)
{
	mScatterSize = (count + 1) * sizeof(Scatter);
	if (!(mScatter = (Scatter *)::realloc(mScatter, mScatterSize)))
		UnixError::throwMe(ENOMEM);
	::memset(mScatter, 0, mScatterSize);
	return mScatter;
}

//
// Keep the allocated size of the (static) CodeDirectory consistent with
// the version chosen. We dynamically picked the least-needed version
// to provide stability of virtual signatures.
//
size_t CodeDirectory::Builder::fixedSize(const uint32_t version)
{
	size_t cdSize = sizeof(CodeDirectory);
	if (version < supportsPreEncrypt)
		cdSize -= sizeof(mDir->runtime) + sizeof(mDir->preEncryptOffset);
	if (version < supportsExecSegment)
		cdSize -= sizeof(mDir->execSegBase) + sizeof(mDir->execSegLimit) + sizeof(mDir->execSegFlags);
	if (version < supportsCodeLimit64)
		cdSize -= sizeof(mDir->spare3) + sizeof(mDir->codeLimit64);
	if (version < supportsTeamID)
		cdSize -= sizeof(mDir->teamIDOffset);

	return cdSize;
}

//
// Calculate the size we'll need for the CodeDirectory as described so far
//
size_t CodeDirectory::Builder::size(const uint32_t version)
{
	assert(mExec);			// must have called executable()
	if (mExecLength == 0)
		mExecLength = mExec.fileSize() - mExecOffset;

	// how many code pages?
	if (mExecLength <= 0) {	// no code, no slots
		mCodeSlots = 0;
	} else if (mPageSize == 0) {	// indefinite - one page
		mCodeSlots = 1;
	} else {				// finite - calculate from file size
		mCodeSlots = (mExecLength - 1) / mPageSize + 1;
	}
		
	size_t offset = fixedSize(version);
	size_t offset0 = offset;
	
	offset += mScatterSize;				// scatter vector
	offset += mIdentifier.size() + 1;	// size of identifier (with null byte)
	if (mTeamID.size())
		offset += mTeamID.size() + 1;	// size of teamID (with null byte)
	offset += (mCodeSlots + mSpecialSlots) * mDigestLength; // hash vector

	if (mGeneratePreEncryptHashes || !mPreservedPreEncryptHashMap.empty()) {
		offset += mCodeSlots * mDigestLength;
	}

	if (offset <= offset0)
		UnixError::throwMe(ENOEXEC);

	return offset;
}


//
// Take everything added to date and wrap it up in a shiny new CodeDirectory.
//
// Note that this only constructs a CodeDirectory; it does not touch any subsidiary
// structures (resource tables, etc.), nor does it create any signature to secure
// the CodeDirectory.
// The returned CodeDirectory object is yours, and you may modify it as desired.
// But the memory layout is set here, so the various sizes and counts should be good
// when you call build().
// It's up to us to order the dynamic fields as we wish; but note that we currently
// don't pad them, and so they should be allocated in non-increasing order of required
// alignment. Make sure to keep the code here in sync with the size-calculating code above.
//
CodeDirectory *CodeDirectory::Builder::build()
{
	assert(mExec);			// must have (successfully) called executable()
	uint32_t version;
	
	// size and allocate
	size_t identLength = mIdentifier.size() + 1;
	size_t teamIDLength = mTeamID.size() + 1;
	
	// Determine the version
	if (mGeneratePreEncryptHashes || !mPreservedPreEncryptHashMap.empty() || mRuntimeVersion) {
		version = currentVersion;
	} else if (mExecSegLimit > 0) {
		version = supportsExecSegment;
	} else if (mExecLength > UINT32_MAX) {
		version = supportsCodeLimit64;
	} else if (mTeamID.size()) {
		version = supportsTeamID;
	} else {
		version = supportsScatter;
	}
	
	if (mCodeSlots > UINT32_MAX)	// (still limited to 32 bits)
		MacOSError::throwMe(errSecCSTooBig);
	
	size_t total = size(version);
	if (!(mDir = (CodeDirectory *)calloc(1, total)))	// initialize to zero
		UnixError::throwMe(ENOMEM);

	// fill header
	mDir->initialize(total);
	mDir->version = version;
	mDir->flags = mFlags;
	mDir->nSpecialSlots = (uint32_t)mSpecialSlots;
	mDir->nCodeSlots = (uint32_t)mCodeSlots;
	if (mExecLength > UINT32_MAX) {
		mDir->codeLimit = UINT32_MAX;
		mDir->codeLimit64 = mExecLength;
	} else {
		mDir->codeLimit = uint32_t(mExecLength);
	}
	mDir->hashType = mHashType;
	mDir->platform = mPlatform;
	mDir->hashSize = mDigestLength;
	if (mPageSize) {
		int pglog;
		assert(frexp(mPageSize, &pglog) == 0.5); // must be power of 2
		frexp(mPageSize, &pglog);
		assert(pglog < 256);
		mDir->pageSize = pglog - 1;
	} else
		mDir->pageSize = 0;	// means infinite page size

	mDir->execSegBase = mExecSegOffset;
	mDir->execSegLimit = mExecSegLimit;
	mDir->execSegFlags = mExecSegFlags;
	mDir->runtime = mRuntimeVersion;

	// locate and fill flex fields
	size_t offset = fixedSize(mDir->version);
	
	if (mScatter) {
		mDir->scatterOffset = (uint32_t)offset;
		memcpy(mDir->scatterVector(), mScatter, mScatterSize);
		offset += mScatterSize;
	}

	mDir->identOffset = (uint32_t)offset;
	memcpy(mDir->identifier(), mIdentifier.c_str(), identLength);
	offset += identLength;
	
	if (mTeamID.size()) {
		mDir->teamIDOffset = (uint32_t)offset;
		memcpy(mDir->teamID(), mTeamID.c_str(), teamIDLength);
		offset += teamIDLength;
	}

	// (add new flexibly-allocated fields here)

	/* Pre-encrypt hashes come before normal hashes, so that the kernel can free
	 * the normal, potentially post-encrypt hashes away easily. */
	if (mGeneratePreEncryptHashes || !mPreservedPreEncryptHashMap.empty()) {
		mDir->preEncryptOffset = (uint32_t)offset;
		offset += mCodeSlots * mDigestLength;
	}

	mDir->hashOffset = (uint32_t)(offset + mSpecialSlots * mDigestLength);
	offset += (mSpecialSlots + mCodeSlots) * mDigestLength;

	assert(offset == total);	// matches allocated size

	(void)offset;
	
	// fill special slots
	memset(mDir->getSlotMutable((int)-mSpecialSlots, false), 0, mDigestLength * mSpecialSlots);
	for (size_t slot = 1; slot <= mSpecialSlots; ++slot)
		memcpy(mDir->getSlotMutable((int)-slot, false), specialSlot((SpecialSlot)slot), mDigestLength);
	
	// fill code slots
	mExec.seek(mExecOffset);
	size_t remaining = mExecLength;
	for (unsigned int slot = 0; slot < mCodeSlots; ++slot) {
		size_t thisPage = remaining;
		if (mPageSize)
			thisPage = min(thisPage, mPageSize);
		MakeHash<Builder> hasher(this);
		generateHash(hasher, mExec, mDir->getSlotMutable(slot, false), thisPage);
		if (mGeneratePreEncryptHashes && mPreservedPreEncryptHashMap.empty()) {
			memcpy(mDir->getSlotMutable(slot, true), mDir->getSlot(slot, false),
				   mDir->hashSize);
		}
		remaining -= thisPage;
	}
	assert(remaining == 0);

	PreEncryptHashMap::iterator preEncrypt =
		mPreservedPreEncryptHashMap.find(mHashType);
	if (preEncrypt != mPreservedPreEncryptHashMap.end()) {
		memcpy(mDir->getSlotMutable(0, true),
			   CFDataGetBytePtr(preEncrypt->second),
			   mCodeSlots * mDigestLength);
		mPreservedPreEncryptHashMap.erase(preEncrypt->first); // Releases the CFData memory.
	}
	
	// all done. Pass ownership to caller
	return mDir;
}


}	// CodeSigning
}	// Security
