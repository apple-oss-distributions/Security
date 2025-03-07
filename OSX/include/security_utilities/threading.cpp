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


//
// threading - generic thread support
//
#include <security_utilities/threading.h>
#include <security_utilities/globalizer.h>
#include <security_utilities/memutils.h>
#include <utilities/debugging.h>

#include <unistd.h>     // WWDC 2007 thread-crash workaround
#include <syslog.h>     // WWDC 2007 thread-crash workaround

//
// Thread-local storage primitive
//
ThreadStoreSlot::ThreadStoreSlot(Destructor *destructor)
{
    if (int err = pthread_key_create(&mKey, destructor))
        UnixError::throwMe(err);
}

ThreadStoreSlot::~ThreadStoreSlot()
{
    //@@@ if we wanted to dispose of pending task objects, we'd have
    //@@@ to keep a set of them and delete them explicitly here
    pthread_key_delete(mKey);
}


//
// Mutex implementation
//
struct MutexAttributes {
	pthread_mutexattr_t recursive;
	pthread_mutexattr_t checking;
	
	MutexAttributes()
	{
		pthread_mutexattr_init(&recursive);
		pthread_mutexattr_settype(&recursive, PTHREAD_MUTEX_RECURSIVE);
#if !defined(NDEBUG)
		pthread_mutexattr_init(&checking);
		pthread_mutexattr_settype(&checking, PTHREAD_MUTEX_ERRORCHECK);
#endif //NDEBUG
	}
};

static ModuleNexus<MutexAttributes> mutexAttrs;


Mutex::Mutex()
{
	check(pthread_mutex_init(&me, NULL));
}

Mutex::Mutex(Type type)
{
	switch (type) {
	case normal:
		check(pthread_mutex_init(&me, IFELSEDEBUG(&mutexAttrs().checking, NULL)));
		break;
	case recursive:		// requested recursive (is also checking, always)
		check(pthread_mutex_init(&me, &mutexAttrs().recursive));
		break;
	};
}


Mutex::~Mutex()
{
    int result = pthread_mutex_destroy(&me);
    if(result) {
        secerror("Probable bug: error destroying Mutex: %d", result);
    }
	check(result);
}


void Mutex::lock()
{
	check(pthread_mutex_lock(&me));
}


bool Mutex::tryLock()
{
	if (int err = pthread_mutex_trylock(&me)) {
		if (err != EBUSY)
			UnixError::throwMe(err);
		return false;
	}

	return true;
}


void Mutex::unlock()
{
    int result = pthread_mutex_unlock(&me);
	check(result);
}


//
// Condition variables
//
Condition::Condition(Mutex &lock) : mutex(lock)
{
    check(pthread_cond_init(&me, NULL));
}

Condition::~Condition()
{
	check(pthread_cond_destroy(&me));
}

void Condition::wait()
{
    check(pthread_cond_wait(&me, &mutex.me));
}

void Condition::signal()
{
    check(pthread_cond_signal(&me));
}

void Condition::broadcast()
{
    check(pthread_cond_broadcast(&me));
}


//
// CountingMutex implementation.
//
void CountingMutex::enter()
{
    lock();
    mCount++;
    unlock();
}

bool CountingMutex::tryEnter()		
{
    if (!tryLock())
        return false;
    mCount++;
    unlock();
    return true;
}

void CountingMutex::exit()
{
    lock();
    assert(mCount > 0);
    mCount--;
    unlock();
}

void CountingMutex::finishEnter()
{
    mCount++;
    unlock();
}

void CountingMutex::finishExit()
{
    assert(mCount > 0);
    mCount--; 
    unlock();
}

//
// ReadWriteLock implementation
//
ReadWriteLock::ReadWriteLock() {
    check(pthread_rwlock_init(&mLock, NULL));
}

bool ReadWriteLock::lock() {
    check(pthread_rwlock_rdlock(&mLock));
    return true;
}

bool ReadWriteLock::tryLock() {
    return (pthread_rwlock_tryrdlock(&mLock) == 0);
}

bool ReadWriteLock::writeLock() {
    check(pthread_rwlock_wrlock(&mLock));
    return true;
}

bool ReadWriteLock::tryWriteLock() {
    return (pthread_rwlock_trywrlock(&mLock) == 0);
}

void ReadWriteLock::unlock() {
    check(pthread_rwlock_unlock(&mLock));
}

//
// StReadWriteLock implementation
//
bool StReadWriteLock::lock() {
    switch(mType) {
        case Read:     mIsLocked = mRWLock.lock(); break;
        case TryRead:  mIsLocked = mRWLock.tryLock(); break;
        case Write:    mIsLocked = mRWLock.writeLock(); break;
        case TryWrite: mIsLocked = mRWLock.tryWriteLock(); break;
    }
    return mIsLocked;
}

void StReadWriteLock::unlock() {
    mRWLock.unlock();
    mIsLocked = false;
}

bool StReadWriteLock::isLocked() {
    return mIsLocked;
}



//
// Threads implementation
//
Thread::~Thread()
{
}

void Thread::threadRun()
{
    pthread_t pt;
    pthread_attr_t ptattrs;
    int err, ntries = 10;       // 10 is arbitrary

    if ((err = pthread_attr_init(&ptattrs)) ||
        (err = pthread_attr_setdetachstate(&ptattrs, PTHREAD_CREATE_DETACHED)))
    {
        syslog(LOG_ERR, "error %d setting thread detach state", err);
    }
    while ((err = pthread_create(&pt, &ptattrs, runner, this) &&
           --ntries))
    {
        syslog(LOG_ERR, "pthread_create() error %d", err);
        usleep(50000);          // 50 ms is arbitrary
    }
    if (err)
    {
        syslog(LOG_ERR, "too many failed pthread_create() attempts");
    }
    else
        secinfo("thread", "%p created", pt);
}

void *Thread::runner(void *arg)
{
    try // the top level of any running thread of execution must have a try/catch around it,
        // otherwise it will crash if something underneath throws.
    {
        Thread *me = static_cast<Thread *>(arg);
        // me might be freed/deleted/gone after me->threadAction(), so hold onto the thread name separately.
        // N.B.: All current usage passes a constant string as the name param to the Thread ctor.
        // If that changes, we would need to strdup() here & free() before returning below.
        const char *threadName = me->threadName;
        pthread_setname_np(threadName);
        secinfo("thread", "%p: %s starting", pthread_self(), threadName);
        me->threadAction();
        me = NULL; // Don't use me after threadAction()!!!
        secinfo("thread", "%p: %s terminating", pthread_self(), threadName);
        return NULL;
    }
    catch (...)
    {
        return NULL;
    }
}

void Thread::threadYield()
{
	::sched_yield();
}
