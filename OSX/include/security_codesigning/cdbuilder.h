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
#ifndef _H_CDBUILDER
#define _H_CDBUILDER

#include "codedirectory.h"


namespace Security {
namespace CodeSigning {


//
// Builder can construct CodeDirectories from pieces:
//	Builder builder(...);
//	builder.variousSetters(withSuitableData);
//  CodeDirectory *result = builder.build();
// Builder is not reusable.
//
class CodeDirectory::Builder : public RefCount {
	NOCOPY(Builder)
public:
	Builder(HashAlgorithm digestAlgorithm);
	~Builder();
	
	void executable(string path, size_t pagesize, size_t offset, size_t length);
	void reopen(string path, size_t offset, size_t length);
	bool opened();

	void specialSlot(SpecialSlot slot, CFDataRef data);
	void identifier(const std::string &code) { mIdentifier = code; }
	void teamID(const std::string &team) { mTeamID = team; }
	void flags(uint32_t f) { mFlags = f; }
	void platform(uint8_t p) { mPlatform = p; }
	std::set<Slot> filledSpecialSlots() const { return mFilledSpecialSlots; }
	
	Scatter *scatter(unsigned count);			// allocate that many scatter elements (w/o sentinel)
	Scatter *scatter() { return mScatter; }		// return already allocated scatter vector

	void execSeg(uint64_t base, uint64_t limit, uint64_t flags) {
		mExecSegOffset = base; mExecSegLimit = limit; mExecSegFlags = flags; }
	void addExecSegFlags(uint64_t flags) { mExecSegFlags |= flags; }

	typedef std::map<CodeDirectory::HashAlgorithm, CFCopyRef<CFDataRef> >
		PreEncryptHashMap;

	void generatePreEncryptHashes(bool pre) { mGeneratePreEncryptHashes = pre; }
	void preservePreEncryptHashMap(PreEncryptHashMap preEncryptHashMap) {
		mPreservedPreEncryptHashMap = preEncryptHashMap;
	}

	void runTimeVersion(uint32_t runtime) {
		mRuntimeVersion = runtime;
	}

	size_t size(const uint32_t version);		// calculate size
	CodeDirectory *build();						// build CodeDirectory and return it
    size_t fixedSize(const uint32_t version);	// calculate fixed size of the CodeDirectory
	
	uint32_t hashType() const { return mHashType; }

	DynamicHash *getHash() const { return CodeDirectory::hashFor(this->mHashType); }
	
private:
	Hashing::Byte *specialSlot(SpecialSlot slot)
		{ assert(slot > 0 && slot <= cdSlotMax); return mSpecial + (slot - 1) * mDigestLength; }
	Hashing::Byte *specialSlot(SpecialSlot slot) const
		{ assert(slot > 0 && slot <= cdSlotMax); return mSpecial + (slot - 1) * mDigestLength; }
	
private:
	Hashing::Byte *mSpecial;					// array of special slot hashes
	std::set<Slot> mFilledSpecialSlots;			// special slots filled with values
	UnixPlusPlus::AutoFileDesc mExec;			// main executable file
	size_t mExecOffset;							// starting offset in mExec
	size_t mExecLength;							// total bytes of file to sign
	size_t mPageSize;							// page size of executable (bytes)
	uint32_t mFlags;							// CodeDirectory flags
	uint32_t mHashType;							// digest algorithm code
	uint8_t mPlatform;							// platform identifier
	uint32_t mDigestLength;						// number of bytes in a single glue digest
	std::string mIdentifier;					// canonical identifier
	std::string mTeamID;                        // team identifier
	
	size_t mSpecialSlots;						// highest special slot set
	size_t mCodeSlots;							// number of code pages (slots)
	
	Scatter *mScatter;							// scatter vector
	size_t mScatterSize;						// number of scatter elements allocated (incl. sentinel)

	uint64_t mExecSegOffset;					// starting offset of executable segment
	uint64_t mExecSegLimit;						// limit of executable segment
	uint64_t mExecSegFlags;						// executable segment flags

	bool mGeneratePreEncryptHashes;				// whether to also generate new pre-encrypt hashes
	PreEncryptHashMap mPreservedPreEncryptHashMap; // existing pre-encrypt hashes to be set

	uint32_t mRuntimeVersion;					// Hardened Runtime Version

	CodeDirectory *mDir;						// what we're building
};


}	// CodeSigning
}	// Security


#endif //_H_CDBUILDER
