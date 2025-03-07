/*
 * Copyright (c) 2006,2011-2014 Apple Inc. All Rights Reserved.
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
// blob - generic extensible binary blob frame
//
// To define a new type of binary blob:
//   class MyBlob : public Blob<MyBlob, magic number> { ... }
// Pick a unique magic number (32-bit). Blobs are understood to be a MyBlob
// header possibly followed by more data as a contiguous memory area. Length
// is overall (including the header), so a fixed-size blob would have length
// sizeof(MyBlob). Both length and magic are stored in NBO.
//
// You are highly encouraged to follow these rules:
//	Store all integers in NBO, including offsets.
//  Use internal offsets to "point to" dynamically-sized elements past the
//   header (using the at<Type>(offset) method for access).
//  Don't use pointers in your blob.
// If you follow those rules, your blobs will be fully relocatable, byte-order
// independent, and generally spreading happiness around your code.
//
#ifndef _H_BLOB
#define _H_BLOB

#include <security_utilities/endian.h>
#include <security_utilities/memutils.h>
#include <security_utilities/errors.h>
#include <security_utilities/cfutilities.h>

namespace Security {


//
// All blobs in memory have this form.
// You can have polymorphic memory blobs (C style) using different magics numbers.
//
class BlobCore {
public:
	typedef uint32_t Offset;
	typedef uint32_t Magic;

	Magic magic() const { return mMagic; }
	size_t length() const { return mLength; }
	
	void initialize(Magic magic, size_t length = 0)
	{ mMagic = magic; mLength = (uint32_t)length; }
	
	bool validateBlob(Magic magic, size_t minSize = 0, size_t maxSize = 0) const;

	template <class T, class Offset>
	T *at(Offset offset)
	{ return LowLevelMemoryUtilities::increment<T>(this, offset); }
	
	template <class T, class Offset>
	const T *at(Offset offset) const
	{ return LowLevelMemoryUtilities::increment<const T>(this, offset); }
	
	template <class Offset1, class Offset2>
	bool contains(Offset1 offset, Offset2 size) const
	{ return offset >= 0 && size_t(offset) >= sizeof(BlobCore) && (size_t(offset) + size) <= this->length(); }
	
	template <class Base, class Offset>
	bool contains(Base *ptr, Offset size) const
	{ return contains(LowLevelMemoryUtilities::difference(ptr, this), size); }

	char *stringAt(Offset offset);
	const char *stringAt(Offset offset) const;

	void *data()						{ return this; }
	const void *data() const			{ return this; }
	void length(size_t size)			{ mLength = (uint32_t)size; }

	BlobCore *clone() const
	{
		if (BlobCore *copy = (BlobCore *)malloc(this->length())) {
			memcpy(copy, this, this->length());
			return copy;
		}
		UnixError::throwMe(ENOMEM);
	}
	
    // Valid for as long as the blob is valid
    CFDataRef innerData() const
    {
        return CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, this->at<UInt8>(sizeof(BlobCore)), length() - sizeof(BlobCore), kCFAllocatorNull);
    }
    
	template <class BlobType>
	bool is() const { return magic() == BlobType::typeMagic; }
	
	static BlobCore *readBlob(std::FILE *file)	{ return readBlob(file, 0, 0, 0); }
	static BlobCore *readBlob(int fd)			{ return readBlob(fd, 0, 0, 0); }
	
protected:
	static BlobCore *readBlob(std::FILE *file, uint32_t magic, size_t minSize, size_t maxSize); // streaming
	static BlobCore *readBlob(int fd, uint32_t magic, size_t minSize, size_t maxSize); // streaming
	static BlobCore *readBlob(int fd, size_t offset, uint32_t magic, size_t minSize, size_t maxSize); // pread(2)@offset
	
protected:
	Endian<uint32_t> mMagic;
	Endian<uint32_t> mLength;
};


// basic validation helper
inline bool BlobCore::validateBlob(Magic magic, size_t minSize /* = 0 */, size_t maxSize /* = 0 */) const
{
	uint32_t length = this->mLength;
	if (magic && magic != this->mMagic) {
		errno = EINVAL;
		return false;
	}
	if (minSize ? (length < minSize) : (length < sizeof(BlobCore))) {
		errno = EINVAL;
		return false;
	}
	if (maxSize && length > maxSize) {
		errno = ENOMEM;
		return false;
	}
	return true;
}


//
// Typed Blobs (BlobCores that know their real type and magic)
//
template <class BlobType, uint32_t _magic>
class Blob: public BlobCore {
public:
	void initialize(size_t size = 0)	{ BlobCore::initialize(_magic, size); }
	
	static const Magic typeMagic = _magic;
	
	bool validateBlob() const
	{ return BlobCore::validateBlob(_magic, sizeof(BlobType)); }
	
	bool validateBlob(size_t extLength) const
	{ return extLength >= sizeof(BlobType) && validateBlob() && mLength == extLength; }
	
	static BlobType *specific(BlobCore *blob, bool unalloc = false)
	{
		if (BlobType *p = static_cast<BlobType *>(blob)) {
			if (p->validateBlob())
				return p;
			if (unalloc)
				::free(p);
		}
		return NULL;
	}
	
	static const BlobType *specific(const BlobCore *blob)
	{
		const BlobType *p = static_cast<const BlobType *>(blob);
		if (p && p->validateBlob())
			return p;
		return NULL;
	}
    
    static inline CFDataRef blobify (CFDataRef content)
    {
        CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault, 0);
        CFDataSetLength(data, CFDataGetLength(content) + sizeof(BlobCore));
        if (!data) {
            MacOSError::throwMe(errSecAllocate);
        }
        Blob<BlobType, _magic>* blob = reinterpret_cast<Blob<BlobType, _magic>*>(CFDataGetMutableBytePtr(data));
        blob->initialize(sizeof(BlobCore) + CFDataGetLength(content));
        memcpy(blob->at<void*>(sizeof(Blob)), CFDataGetBytePtr(content), CFDataGetLength(content));
        return data;
    }
	
	BlobType *clone() const
	{ assert(validateBlob()); return specific(this->BlobCore::clone());	}

	static BlobType *readBlob(int fd)
	{ return specific(BlobCore::readBlob(fd, _magic, sizeof(BlobType), 0), true); }

	static BlobType *readBlob(int fd, size_t offset, size_t maxSize = 0)
	{ return specific(BlobCore::readBlob(fd, offset, _magic, sizeof(BlobType), maxSize), true); }

	static BlobType *readBlob(std::FILE *file)
	{ return specific(BlobCore::readBlob(file, _magic, sizeof(BlobType), 0), true); }
};


//
// A generic blob wrapped around arbitrary (flat) binary data.
// This can be used to "regularize" plain binary data, so it can be handled
// as a genuine Blob (e.g. for insertion into a SuperBlob).
//
class BlobWrapper : public Blob<BlobWrapper, 0xfade0b01> {
public:
	static BlobWrapper *alloc(size_t length, Magic magic = BlobWrapper::typeMagic);
	static BlobWrapper *alloc(const void *data, size_t length, Magic magic = BlobWrapper::typeMagic);
	
	unsigned char dataArea[0];
	
	// override data/length to point to the payload (only)
	void *data() { return dataArea; }
	const void *data() const { return dataArea; }
	size_t length() const { return BlobCore::length() - sizeof(BlobCore); }
};


}	// Security

#endif //_H_BLOB
