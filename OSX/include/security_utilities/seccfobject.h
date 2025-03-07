/*
 * Copyright (c) 2000-2004,2011,2013-2014 Apple Inc. All Rights Reserved.
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



#ifndef _SECCFOBJECT_H
#define _SECCFOBJECT_H

#include <CoreFoundation/CFRuntime.h>
#include <new>
#include "threading.h"
#include <os/lock.h>

#if( __cplusplus <= 201103L)
#include <stdatomic.h>
#else
#include <atomic>
#endif

namespace Security {

class CFClass;

#define SECCFFUNCTIONS_BASE(OBJTYPE, APIPTR) \
\
operator APIPTR() const \
{ return (APIPTR)(this->operator CFTypeRef()); } \
\
OBJTYPE *retain() \
{ SecCFObject::handle(true); return this; } \
APIPTR CF_RETURNS_RETAINED handle() \
{ return (APIPTR)SecCFObject::handle(true); } \
APIPTR handle(bool retain) \
{ return (APIPTR)SecCFObject::handle(retain); }

#define SECCFFUNCTIONS_CREATABLE(OBJTYPE, APIPTR, CFCLASS) \
SECCFFUNCTIONS_BASE(OBJTYPE, APIPTR)\
\
void *operator new(size_t size)\
{ return SecCFObject::allocate(size, CFCLASS); }

#define SECCFFUNCTIONS(OBJTYPE, APIPTR, ERRCODE, CFCLASS) \
SECCFFUNCTIONS_CREATABLE(OBJTYPE, APIPTR, CFCLASS) \
\
static OBJTYPE *required(APIPTR ptr) \
{ if (OBJTYPE *p = dynamic_cast<OBJTYPE *>(SecCFObject::required(ptr, ERRCODE))) \
	return p; else MacOSError::throwMe(ERRCODE); } \
\
static OBJTYPE *optional(APIPTR ptr) \
{ if (SecCFObject *p = SecCFObject::optional(ptr)) \
	if (OBJTYPE *pp = dynamic_cast<OBJTYPE *>(p)) return pp; else MacOSError::throwMe(ERRCODE); \
  else return NULL; }

#define SECALIGNUP(SIZE, ALIGNMENT) (((SIZE - 1) & ~(ALIGNMENT - 1)) + ALIGNMENT)

struct SecRuntimeBase: CFRuntimeBase
{
	atomic_flag isOld;
};

class SecCFObject
{
private:
	void *operator new(size_t);

	// Align up to a multiple of 16 bytes
	static const size_t kAlignedRuntimeSize = SECALIGNUP(sizeof(SecRuntimeBase), 4);

    uint32_t mRetainCount;
    os_unfair_lock mRetainLock;

public:
	// For use by SecPointer only. Returns true once the first time it's called after the object has been created.
	bool isNew()
	{
		SecRuntimeBase *base = reinterpret_cast<SecRuntimeBase *>(reinterpret_cast<uint8_t *>(this) - kAlignedRuntimeSize);

        // atomic flags start clear, and like to go high.
        return !atomic_flag_test_and_set(&(base->isOld));
	}

	static SecCFObject *optional(CFTypeRef) _NOEXCEPT;
	static SecCFObject *required(CFTypeRef, OSStatus error);
	static void *allocate(size_t size, const CFClass &cfclass);

    SecCFObject();
	virtual ~SecCFObject();
    uint32_t updateRetainCount(intptr_t direction, uint32_t *oldCount);
    uint32_t getRetainCount() {return updateRetainCount(0, NULL);}

	static void operator delete(void *object) _NOEXCEPT;
	virtual operator CFTypeRef() const _NOEXCEPT
	{
		return reinterpret_cast<CFTypeRef>(reinterpret_cast<const uint8_t *>(this) - kAlignedRuntimeSize);
	}

	// This bumps up the retainCount by 1, by calling CFRetain(), iff retain is true
	CFTypeRef handle(bool retain = true) _NOEXCEPT;

    virtual bool equal(SecCFObject &other);
    virtual CFHashCode hash();
	virtual CFStringRef copyFormattingDesc(CFDictionaryRef dict);
	virtual CFStringRef copyDebugDesc();
	virtual void aboutToDestruct();
	virtual Mutex* getMutexForObject() const;
    virtual bool mayDelete();
};

//
// A pointer type for SecCFObjects.
// T must be derived from SecCFObject.
//
class SecPointerBase
{
public:
	SecPointerBase() : ptr(NULL)
	{}
	SecPointerBase(const SecPointerBase& p);
	SecPointerBase(SecCFObject *p);
	~SecPointerBase();
	SecPointerBase& operator = (const SecPointerBase& p);

protected:
 	void assign(SecCFObject * p);
	void copy(SecCFObject * p);
	SecCFObject *ptr;
};

template <class T>
class SecPointer : public SecPointerBase
{
public:
	SecPointer() : SecPointerBase() {}
	SecPointer(const SecPointer& p) : SecPointerBase(p) {}
	SecPointer(T *p): SecPointerBase(p) {}
	SecPointer &operator =(T *p) { this->assign(p); return *this; }
	SecPointer &take(T *p) { this->copy(p); return *this; }
	T *yield() { T *result = static_cast<T *>(ptr); ptr = NULL; return result; }
	
	// dereference operations
    T* get () const				{ return static_cast<T*>(ptr); }	// mimic unique_ptr
	operator T * () const		{ return static_cast<T*>(ptr); }
	T * operator -> () const	{ return static_cast<T*>(ptr); }
	T & operator * () const		{ return *static_cast<T*>(ptr); }

    SecPointer& operator=(const SecPointer& other) { SecPointerBase::operator=(other); return *this; }
};

template <class T>
bool operator <(const SecPointer<T> &r1, const SecPointer<T> &r2)
{
	T *p1 = r1.get(), *p2 = r2.get();
	return p1 && p2 ? *p1 < *p2 : p1 < p2;
}

template <class T>
bool operator ==(const SecPointer<T> &r1, const SecPointer<T> &r2)
{
	T *p1 = r1.get(), *p2 = r2.get();
	return p1 && p2 ? *p1 == *p2 : p1 == p2;
}

template <class T>
bool operator !=(const SecPointer<T> &r1, const SecPointer<T> &r2)
{
	T *p1 = r1.get(), *p2 = r2.get();
	return p1 && p2 ? *p1 != *p2 : p1 != p2;
}

} // end namespace Security


#endif
