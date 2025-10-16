/*
 * Copyright (c) 2000-2004,2011-2014 Apple Inc. All Rights Reserved.
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
// CoreFoundation related utilities
//
#include <security_utilities/cfutilities.h>
#include <security_utilities/errors.h>
#include <security_utilities/debugging.h>
#include <security_utilities/unix++.h>
#include <utilities/SecCFRelease.h>
#include <cstdarg>
#include <vector>

#include <sys/mman.h>

namespace Security {


ModuleNexus<CFEmptyArray> cfEmptyArray;

CFEmptyArray::CFEmptyArray()
{
	mArray = CFArrayCreate(NULL, NULL, 0, NULL);
}


//
// Turn a C(++) string into a CFURLRef indicating a file: path
//
CFURLRef makeCFURL(const char *s, bool isDirectory, CFURLRef base)
{
	if (base)
		return CFURLCreateWithFileSystemPathRelativeToBase(NULL,
			CFTempString(s), kCFURLPOSIXPathStyle, isDirectory, base);
	else
		return CFURLCreateWithFileSystemPath(NULL,
			CFTempString(s), kCFURLPOSIXPathStyle, isDirectory);
}

CFURLRef makeCFURL(CFStringRef s, bool isDirectory, CFURLRef base)
{
	if (base)
		return CFURLCreateWithFileSystemPathRelativeToBase(NULL, s, kCFURLPOSIXPathStyle, isDirectory, base);
	else
		return CFURLCreateWithFileSystemPath(NULL, s, kCFURLPOSIXPathStyle, isDirectory);
}


//
// CFMallocData objects
//
CFMallocData::operator CFDataRef ()
{
	CFDataRef result = makeCFDataMalloc(mData, mSize);
	if (!result)
		CFError::throwMe();
	mData = NULL;	// release ownership
	return result;
}


//
// Make CFDictionaries from stuff
//
CFDictionaryRef makeCFDictionary(unsigned count, ...)
{
	CFTypeRef keys[count], values[count];
	va_list args;
	va_start(args, count);
	for (unsigned n = 0; n < count; n++) {
		keys[n] = va_arg(args, CFTypeRef);
		values[n] = va_arg(args, CFTypeRef);
	}
	va_end(args);
	return CFDictionaryCreate(NULL, (const void **)keys, (const void **)values, count,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
}

CFMutableDictionaryRef makeCFMutableDictionary()
{
	if (CFMutableDictionaryRef r = CFDictionaryCreateMutable(NULL, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks))
		return r;
	CFError::throwMe();
}

CFMutableDictionaryRef makeCFMutableDictionary(unsigned count, ...)
{
	CFMutableDictionaryRef dict = makeCFMutableDictionary();
	if (count > 0) {
		va_list args;
		va_start(args, count);
		for (unsigned n = 0; n < count; n++) {
			CFTypeRef key = va_arg(args, CFTypeRef);
			CFTypeRef value = va_arg(args, CFTypeRef);
			CFDictionaryAddValue(dict, key, value);
		}
		va_end(args);
	}
	return dict;
}

CFMutableDictionaryRef makeCFMutableDictionary(CFDictionaryRef dict)
{
	if (CFMutableDictionaryRef r = CFDictionaryCreateMutableCopy(NULL, 0, dict))
		return r;
	CFError::throwMe();
}

CFDictionaryRef makeCFDictionaryFrom(CFDataRef data)
{
	if (data) {
		CFPropertyListRef plist = CFPropertyListCreateFromXMLData(NULL, data,
			kCFPropertyListImmutable, NULL);
		if (plist && CFGetTypeID(plist) != CFDictionaryGetTypeID())
			CFError::throwMe();
		return CFDictionaryRef(plist);
	} else
		return NULL;
	
}

CFDictionaryRef makeCFDictionaryFrom(const void *data, size_t length)
{
	return makeCFDictionaryFrom(CFTempData(data, length).get());
}



static void cfarrayApplyBlock_func(const void *value, const void *ctx)
{
    CFArrayApplierBlock block = CFArrayApplierBlock(ctx);
    block(value);
}
void cfArrayApplyBlock(CFArrayRef array, CFRange range, CFArrayApplierBlock block)
{
    CFArrayApplyFunction(array, range, (CFArrayApplierFunction)cfarrayApplyBlock_func, block);
}
void cfArrayApplyBlock(CFArrayRef array, CFArrayApplierBlock block)
{
    CFRange range = CFRangeMake(0, CFArrayGetCount(array));
    cfArrayApplyBlock(array, range, block);
}

static void cfdictionaryApplyBlock_func(const void *key, const void *value, void *ctx)
{
    CFDictionaryApplierBlock block = CFDictionaryApplierBlock(ctx);
    block(key, value);
}
void cfDictionaryApplyBlock(CFDictionaryRef dict, CFDictionaryApplierBlock block)
{
    CFDictionaryApplyFunction(dict, cfdictionaryApplyBlock_func, block);
}


//
// Turn a CFString into a UTF8-encoded C++ string.
// If release==true, the argument will be CFReleased even in case of error.
//
string cfString(CFStringRef str)
{
	if (!str)
		return "";
	// quick path first
	if (const char *s = CFStringGetCStringPtr(str, kCFStringEncodingUTF8)) {
		return s;
	}
	
	// need to extract into buffer
	string ret;
	CFIndex length = CFStringGetMaximumSizeForEncoding(CFStringGetLength(str), kCFStringEncodingUTF8);
	std::vector<char> buffer;
	buffer.resize(length + 1);
	if (CFStringGetCString(str, &buffer[0], length + 1, kCFStringEncodingUTF8))
		ret = &buffer[0];
	return ret;
}

string cfStringRelease(CFStringRef CF_CONSUMED inStr)
{
	CFRef<CFStringRef> str(inStr);
	return cfString(str);
}

string cfString(CFURLRef inUrl)
{
	if (!inUrl)
		CFError::throwMe();
	
	UInt8 buffer[PATH_MAX+1];
	if (CFURLGetFileSystemRepresentation(inUrl, true, buffer, sizeof(buffer)))
		return string(reinterpret_cast<char *>(buffer));
	else
		CFError::throwMe();
}
    
string cfStringRelease(CFURLRef CF_CONSUMED inUrl)
{
	CFRef<CFURLRef> bundle(inUrl);
	return cfString(bundle);
}
    
string cfString(CFBundleRef inBundle)
{
	if (!inBundle)
		CFError::throwMe();
	return cfStringRelease(CFBundleCopyBundleURL(inBundle));
}

string cfStringRelease(CFBundleRef CF_CONSUMED inBundle)
{
	CFRef<CFBundleRef> bundle(inBundle);
	return cfString(bundle);
}

    
string cfString(CFTypeRef it, OSStatus err)
{
	if (it == NULL)
		MacOSError::throwMe(err);
	CFTypeID id = CFGetTypeID(it);
	if (id == CFStringGetTypeID())
		return cfString(CFStringRef(it));
	else if (id == CFURLGetTypeID())
		return cfString(CFURLRef(it));
	else if (id == CFBundleGetTypeID())
		return cfString(CFBundleRef(it));
    else {
        return cfStringRelease(CFCopyDescription(it));
    }
}


//
// CFURLAccess wrappers for specific purposes
//
CFDataRef cfReadFile(CFURLRef url)
{
	assert(url);
	CFDataRef data;
	SInt32 error;
	if (CFURLCreateDataAndPropertiesFromResource(NULL, url,
		&data, NULL, NULL, &error)) {
		return data;
	} else {
		secinfo("cfloadfile", "failed to fetch %s error=%d", cfString(url).c_str(), int(error));
		return NULL;
	}
}

CFDataRef cfReadFile(int fd, size_t bytes)
{
	uint8_t *buffer = (uint8_t *) malloc(bytes);

	if (buffer == NULL)
		return NULL;

	if (read(fd, buffer, bytes) != bytes) {
		free(buffer);
		return NULL;
	}

	CFDataRef result = CFDataCreateWithBytesNoCopy(kCFAllocatorMalloc, buffer, bytes, kCFAllocatorMalloc);

	// If CFDataCreateWithBytesNoCopy fails, the buffer is not free()-ed
	if (result == NULL) {
		free(buffer);
		return NULL;
	}

	return result;
}

//
// CFArray creators
//
CFArrayRef makeCFArray(CFIndex count, ...)
{
	CFTypeRef elements[count];
	va_list args;
	va_start(args, count);
	for (CFIndex n = 0; n < count; n++)
		elements[n] = va_arg(args, CFTypeRef);
	va_end(args);
	return CFArrayCreate(NULL, elements, count, &kCFTypeArrayCallBacks);
}

CFMutableArrayRef makeCFMutableArray(CFIndex count, ...)
{
	CFMutableArrayRef array = CFArrayCreateMutable(NULL, count, &kCFTypeArrayCallBacks);
	va_list args;
	va_start(args, count);
	for (CFIndex n = 0; n < count; n++)
		CFArrayAppendValue(array, va_arg(args, CFTypeRef));
	va_end(args);
	return array;
}

struct mmapAllocatorInfo {
    size_t size;
};

static void *mmapDeallocatorAllocate(CFIndex allocSize, CFOptionFlags hint, void *info) {
    /* We do nothing here. makeMappedData already did everything, the only thing we want
     * this allocator for is to deallocate. */
    return NULL;
}

static void mmapDeallocatorDeallocate(void *ptr, void *info) {
    struct mmapAllocatorInfo const *mmapInfo =
    reinterpret_cast<struct mmapAllocatorInfo const *>
    (CFDataGetBytePtr(reinterpret_cast<CFDataRef>(info)));

    if (munmap(ptr, mmapInfo->size) != 0) {
        secdebug("mmapdeallocatordeallocate", "could not unmap: errno %d", errno);
    }
}

static CFIndex mmapPreferredSize(CFIndex size, CFOptionFlags hint, void *info) {
    return size + sizeof(struct mmapAllocatorInfo); // No need to be exact here.
}

CFDataRef cfMapFile(int fd, size_t bytes)
{
    off_t offset = lseek(fd, 0, SEEK_CUR);

    if (offset == -1) {
        secdebug("cfmapfile", "cannot get file offset, errno %d", errno);
    }

    uint8_t *buf = (uint8_t*)mmap(NULL, bytes, PROT_READ, MAP_PRIVATE, fd, offset);

    if (buf == MAP_FAILED) {
        secdebug("cfmapfile", "cannot mmap file, errno %d", errno);
        return NULL;
    }

    /* We're finally set up. */

    struct mmapAllocatorInfo info = {
        .size = bytes
    };

    CFRef<CFDataRef> infoData = makeCFData(&info, sizeof(info));

    CFAllocatorContext context = {
        .version = 0,
        .info = NULL,
        .retain = CFRetain,
        .release = CFRelease,
        .copyDescription = NULL,
        .allocate = mmapDeallocatorAllocate,
        .reallocate = NULL,
        .deallocate = mmapDeallocatorDeallocate,
        .preferredSize = mmapPreferredSize
    };

    context.info = (void*)infoData.get();

    CFRef<CFAllocatorRef> deallocator = CFAllocatorCreate(NULL, &context);

    CFDataRef result = CFDataCreateWithBytesNoCopy(NULL, buf, info.size, deallocator.get());

    // If CFDataCreateWithBytesNoCopy fails, the buffer is not unallocated
    if (result == NULL) {
        munmap(buf, bytes);
        return NULL;
    }
    
    return result;
}

CFDataRef cfMapFile(CFURLRef url) {
    string path;

    /* This is contrived,
     * but we want this as compatible to cfLoadFile as possible, which also means
     * not throwing the exceptions that cfString might, as cfLoadFile does not call
     * cfString. */

    try {
        path = cfString(url);
    } catch (...) {
        secdebug("cfmapfile", "Exception while forming path from URL, giving up.");
        return NULL;
    }

    UnixPlusPlus::AutoFileDesc fd(path.c_str(), O_RDONLY, 0666 | UnixPlusPlus::AutoFileDesc::modeMissingOk);

    struct stat st;

    if (!fd.isOpen()) {
        secdebug("cfmapfile", "cannot open file '%s', errno %d", path.c_str(), errno);
        return NULL;
    }

    if (fstat(fd.fd(), &st) != 0) {
        secdebug("cfmapfile", "cannot stat '%s', errno %d", path.c_str(), errno);
        return NULL;
    }

    if (st.st_size < 0) {
        secdebug("cfmapfile", "size for '%s' is negative", path.c_str());
        return NULL;
    }

    return cfMapFile(fd.fd(), fd.fileSize());
}

CFDataRef cfLoadFile(CFURLRef url){
#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    return cfMapFile(url);
#else
    return cfReadFile(url);
#endif
}

CFDataRef cfLoadFile(int fd, size_t bytes){
#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR
    return cfMapFile(fd, bytes);
#else
    return cfReadFile(fd, bytes);
#endif
}


}	// end namespace Security
