/*
 * Copyright (c) 2000-2004,2011-2012,2014 Apple Inc. All Rights Reserved.
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


/*
 * globalizer - multiscope globalization services
 */
#ifndef _H_GLOBALIZER
#define _H_GLOBALIZER

#include <security_utilities/threading.h>
#include <memory>
#include <set>
#include <dispatch/dispatch.h>
#include <libkern/OSAtomic.h>
#include <os/lock.h>

namespace Security {


//
// GlobalNexus is the common superclass of all globality scopes.
// A Nexus is an *access point* to the *single* object of a given
// type in the Nexus's particular scope.
//
class GlobalNexus {
public:
    class Error : public std::exception {
    public:
        virtual ~Error() _NOEXCEPT;
        const char * const message;
        Error(const char *m) : message(m) { }
        const char *what() const _NOEXCEPT { return message; }
    };
};


class ModuleNexusCommon : public GlobalNexus {
private:
    void do_create(void *(*make)());

protected:
    void *create(void *(*make)());
    void lock() {os_unfair_lock_lock(&access);}
    void unlock() {os_unfair_lock_unlock(&access);}

protected:
    // all of these will be statically initialized to zero
	void *pointer;
    dispatch_once_t once;
    os_unfair_lock access;
};

template <class Type>
class ModuleNexus : public ModuleNexusCommon {
public:
    Type &operator () () 
    {
        lock();
        
        try
        {
            if (pointer == NULL)
            {
                pointer = create(make);
            }
            
            unlock();
        }
        catch (...)
        {
            unlock();
            throw;
        }
        
		return *reinterpret_cast<Type *>(pointer);
    }
	
	// does the object DEFINITELY exist already?
	bool exists() const
	{
        bool result;
        lock();
        result = pointer != NULL;
        unlock();
        return result;
	}
    
	// destroy the object (if any) and start over - not really thread-safe
    void reset()
    {
        lock();
        if (pointer != NULL)
        {
            delete reinterpret_cast<Type *>(pointer);
            pointer = NULL;
            once = 0;
        }
        unlock();
    }
    
private:
    static void *make() { return new Type; }
};

template <class Type>
class CleanModuleNexus : public ModuleNexus<Type> {
public:
    ~CleanModuleNexus()
    {
        secinfo("nexus", "ModuleNexus %p destroyed object 0x%x",
			this, ModuleNexus<Type>::pointer);
        delete reinterpret_cast<Type *>(ModuleNexus<Type>::pointer);
    }
};

typedef std::set<void*> RetentionSet;

//
// A thread-scope nexus is tied to a particular native thread AND
// a particular nexus object. Its scope is all code in any one thread
// that access that particular Nexus object. Any number of Nexus objects
// can exist, and each implements a different scope for each thread.
// NOTE: ThreadNexus is dynamically constructed. If you want static,
// zero-initialization ThreadNexi, put them inside a ModuleNexus.
//
template <class Type>
class ThreadNexus : public GlobalNexus {
public:
    ThreadNexus() : mSlot(true) { }

    Type &operator () ()
    {
        // no thread contention here!
        if (Type *p = mSlot)
            return *p;
        mSlot = new Type;
        return *mSlot;
    }

private:
    PerThreadPointer<Type> mSlot;
};


} // end namespace Security

#endif //_H_GLOBALIZER
