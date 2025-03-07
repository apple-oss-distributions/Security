/*
 * Copyright (c) 2000-2007,2011-2013 Apple Inc. All Rights Reserved.
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
// machserver - C++ shell for writing Mach 3 servers
//
#include "machserver.h"
#include <servers/bootstrap.h>
#include <mach/kern_return.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include "mach_notifyServer.h"
#include <security_utilities/debugging.h>
#include <malloc/malloc.h>

#if defined(USECFCURRENTTIME)
# include <CoreFoundation/CFDate.h>
#else
# include <sys/time.h>
#endif

#define SEC_MACH_AUDIT_TOKEN_PID (5)

namespace Security {
namespace MachPlusPlus {


//
// Global per-thread information
//
ModuleNexus< ThreadNexus<MachServer::PerThread> > MachServer::thread;


//
// Create a server object.
// The resulting object is not "active", and any number of server objects
// can be in this "prepared" state at the same time.
//
MachServer::MachServer()
{ setup("(anonymous)"); }

MachServer::MachServer(const char *name)
	: mServerPort(name, bootstrap)
{ setup(name); }

MachServer::MachServer(const char *name, const Bootstrap &boot)
	: bootstrap(boot), mServerPort(name, bootstrap)
{ setup(name); }

void MachServer::setup(const char *name)
{
	workerTimeout = 60 * 2;	// 2 minutes default timeout
	maxWorkerCount = 100;	// make sure we don't go too wide
	useFloatingThread = false; // tight thread management
    
    mPortSet += mServerPort;
}

MachServer::~MachServer()
{
	// The ReceivePort members will clean themselves up.
	// The bootstrap server will clear us from its map when our receive port dies.
}


//
// Register for mach port notifications
//
void MachServer::notifyIfDead(Port port, bool doNotify) const
{
	if (doNotify)
		port.requestNotify(mServerPort);
	else
		port.cancelNotify();
}

void MachServer::notifyIfUnused(Port port, bool doNotify) const
{
	if (doNotify)
		port.requestNotify(port, MACH_NOTIFY_NO_SENDERS, true);
	else
		port.cancelNotify(MACH_NOTIFY_NO_SENDERS);
}


//
// Initiate service.
// This call will take control of the current thread and use it to service
// incoming requests. The thread will not be released until an error happens, which
// will cause an exception to be thrown. In other words, this never returns normally.
// We may also be creating additional threads to service concurrent requests
// as appropriate.
// @@@ Msg-errors in additional threads are not acted upon.
//
void MachServer::run(mach_msg_size_t maxSize, mach_msg_options_t options)
{
	// establish server-global (thread-shared) parameters
	mMaxSize = maxSize;
	mMsgOptions = options;
	
	// establish the thread pool state
	// (don't need managerLock since we're the only thread as of yet)
	idleCount = workerCount = 1;
	nextCheckTime = Time::now() + workerTimeout;
	leastIdleWorkers = 1;
	highestWorkerCount = 1;
	
	// run server loop in initial (immortal) thread
    secinfo("machserver", "start thread");
	runServerThread(false);
    secinfo("machserver", "end thread");
	
	// primary server thread exited somehow (not currently possible)
	assert(false);
}


//
// This is the core of a server thread at work. It takes over the thread until
// (a) an error occurs, throwing an exception
// (b) low-load timeout happens, causing a normal return (doTimeout only)
// This code was once based on mach_msg_server.c, but it is getting harder to notice
// the lingering resemblance.
//
extern "C" boolean_t cdsa_notify_server(mach_msg_header_t *in, mach_msg_header_t *out);

void MachServer::runServerThread(bool doTimeout)
{
	// allocate request/reply buffers
    Message bufRequest(mMaxSize);
    Message bufReply(mMaxSize);
	
	// all exits from runServerThread are through exceptions
	try {
		// register as a worker thread
		perThread().server = this;

		for (;;) {
			// progress hook
			eventDone();
            
            cleanupWorkers(); // cleanup worker threads that have exited
			
			// process all pending timers
			while (processTimer()) {}
		
			// check for worker idle timeout
			{	StLock<Mutex> _(managerLock);
				// record idle thread low-water mark in scan interval
				if (idleCount < leastIdleWorkers)
					leastIdleWorkers = idleCount;
				
				// perform self-timeout processing
				if (doTimeout) {
					if (workerCount > maxWorkerCount)	// someone reduced maxWorkerCount recently...
						break;							// ... so release this thread immediately
					Time::Absolute rightNow = Time::now();
					if (rightNow >= nextCheckTime) {	// reaping period complete; process
						UInt32 idlers = leastIdleWorkers;
                        secinfo("machserver", "reaping workers: %d %d", (uint32_t) workerCount, (uint32_t) idlers);
						nextCheckTime = rightNow + workerTimeout;
						leastIdleWorkers = INT_MAX;
						if (idlers > 1)					// multiple idle threads throughout measuring interval...
							break;						// ... so release this thread now
					}
				}
			}
			
			// determine next timeout (if any)
            bool indefinite = false;
			Time::Interval timeout = workerTimeout;
			{	StLock<Mutex> _(managerLock);
				if (timers.empty()) {
					indefinite = !doTimeout;
				} else {
					timeout = max(Time::Interval(0), timers.next() - Time::now());
					if (doTimeout && workerTimeout < timeout)
						timeout = workerTimeout;
                }
			}

			// receive next IPC request (or wait for timeout)
			mach_msg_return_t mr = indefinite ?
				mach_msg_overwrite(bufRequest,
					MACH_RCV_MSG | mMsgOptions,
					0, mMaxSize, mPortSet,
					MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL,
					(mach_msg_header_t *) 0, 0)
                    :
				mach_msg_overwrite(bufRequest,
					MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT | mMsgOptions,
					0, mMaxSize, mPortSet,
					mach_msg_timeout_t(timeout.mSeconds()), MACH_PORT_NULL,
					(mach_msg_header_t *) 0, 0);
					
			switch (mr) {
			case MACH_MSG_SUCCESS:
				// process received request message below
				break;
			default:
                secinfo("machserver", "received error: %d", mr);
				continue;
			}
			
			// reset the buffer each time, handlers don't consistently set out params
			bufReply.clearBuffer();

			// process received message
			if (bufRequest.msgId() >= MACH_NOTIFY_FIRST &&
				bufRequest.msgId() <= MACH_NOTIFY_LAST) {
				// mach kernel notification message
				// we assume this is quick, so no thread arbitration here
				mach_msg_audit_trailer_t *tlr = bufRequest.auditTrailer();
				if (tlr == NULL || tlr->msgh_audit.val[SEC_MACH_AUDIT_TOKEN_PID] != 0) {
					secnotice("machserver", "ignoring invalid notify message");
					continue;
				}
				cdsa_notify_server(bufRequest, bufReply);
			} else {
				// normal request message
				StLock<MachServer, &MachServer::busy, &MachServer::idle> _(*this);
                secinfo("machserver", "begin request: %d, %d", bufRequest.localPort().port(), bufRequest.msgId());
				
				// try subsidiary handlers first
				bool handled = false;
				for (HandlerSet::const_iterator it = mHandlers.begin();
						it != mHandlers.end(); it++)
					if (bufRequest.localPort() == (*it)->port()) {
						(*it)->handle(bufRequest, bufReply);
						handled = true;
					}
				if (!handled) {
					// unclaimed, send to main handler
                    handle(bufRequest, bufReply);
                }

                secinfo("machserver", "end request");
			}

			// process reply generated by handler
            if (!(bufReply.bits() & MACH_MSGH_BITS_COMPLEX) &&
                bufReply.returnCode() != KERN_SUCCESS) {
                    if (bufReply.returnCode() == MIG_NO_REPLY)
						continue;
                    // don't destroy the reply port right, so we can send an error message
                    bufRequest.remotePort(MACH_PORT_NULL);
                    mach_msg_destroy(bufRequest);
            }

            if (bufReply.remotePort() == MACH_PORT_NULL) {
                // no reply port, so destroy the reply
                if (bufReply.bits() & MACH_MSGH_BITS_COMPLEX)
                    bufReply.destroy();
                continue;
            }

            /*
             *  We don't want to block indefinitely because the client
             *  isn't receiving messages from the reply port.
             *  If we have a send-once right for the reply port, then
             *  this isn't a concern because the send won't block.
             *  If we have a send right, we need to use MACH_SEND_TIMEOUT.
             *  To avoid falling off the kernel's fast RPC path unnecessarily,
             *  we only supply MACH_SEND_TIMEOUT when absolutely necessary.
             */
            mr = mach_msg_overwrite(bufReply,
                          (MACH_MSGH_BITS_REMOTE(bufReply.bits()) ==
                                                MACH_MSG_TYPE_MOVE_SEND_ONCE) ?
                          MACH_SEND_MSG | mMsgOptions :
                          MACH_SEND_MSG | MACH_SEND_TIMEOUT | mMsgOptions,
                          bufReply.length(), 0, MACH_PORT_NULL,
                          0, MACH_PORT_NULL, NULL, 0);
            switch (mr) {
            case MACH_MSG_SUCCESS:
                break;
            case MACH_SEND_INVALID_DEST:
            case MACH_SEND_TIMED_OUT:
                secinfo("machserver", "send error: %d %d", mr, bufReply.remotePort().port());
                bufReply.destroy();
                break;
            default:
                secinfo("machserver", "send error: %d %d", mr, bufReply.remotePort().port());
                break;
            }

            
            // clean up after the transaction
            releaseDeferredAllocations();
        }
		perThread().server = NULL;
		
	} catch (...) {
		perThread().server = NULL;
		throw;
	}
}


//
// Manage subsidiary port handlers
//
void MachServer::add(Handler &handler)
{
    assert(mHandlers.find(&handler) == mHandlers.end());
    assert(handler.port() != MACH_PORT_NULL);
    mHandlers.insert(&handler);
    mPortSet += handler.port();
}

void MachServer::remove(Handler &handler)
{
    assert(mHandlers.find(&handler) != mHandlers.end());
    mHandlers.erase(&handler);
    mPortSet -= handler.port();
}


//
// Abstract auxiliary message handlers
//
MachServer::Handler::~Handler()
{ /* virtual */ }


//
// Implement a Handler that sends no reply
//
boolean_t MachServer::NoReplyHandler::handle(mach_msg_header_t *in, mach_msg_header_t *out)
{
    // set up reply message to be valid (enough) and read "do not send reply"
    out->msgh_bits = 0;
    out->msgh_remote_port = MACH_PORT_NULL;
    out->msgh_size = sizeof(mig_reply_error_t);
    ((mig_reply_error_t *)out)->RetCode = MIG_NO_REPLY;
    
    // call input-only handler
    return handle(in);
}


//
// Register a memory block for deferred release.
//
void MachServer::releaseWhenDone(Allocator &alloc, void *memory)
{
    if (memory) {
        set<Allocation> &releaseSet = perThread().deferredAllocations;
        assert(releaseSet.find(Allocation(memory, alloc)) == releaseSet.end());
        secinfo("machserver", "allocing register %p with alloc %p", memory, &alloc);
        releaseSet.insert(Allocation(memory, alloc));
    }
}


//
// Run through the accumulated deferred allocations and release them.
// This is done automatically on every pass through the server loop;
// it must be called by subclasses that implement their loop in some
// other way.
// @@@X Needs to be thread local
//
void MachServer::releaseDeferredAllocations()
{
    set<Allocation> &releaseSet = perThread().deferredAllocations;
	for (set<Allocation>::iterator it = releaseSet.begin(); it != releaseSet.end(); it++) {
        secinfo("machserver", "releasing alloc at %p with %p", it->addr, it->allocator);

        // before we release the deferred allocation, zap it so that secrets aren't left in memory
        size_t memSize = malloc_size(it->addr);
        bzero(it->addr, memSize);
		it->allocator->free(it->addr);
    }
	releaseSet.erase(releaseSet.begin(), releaseSet.end());
}


//
// The handler function calls this if it realizes that it might be blocked
// (or doing something that takes a long time). We respond by ensuring that
// at least one more thread is ready to serve requests.
// Calls the threadLimitReached callback in the server object if the thread
// limit has been exceeded and a needed new thread was not created.
//
void MachServer::longTermActivity()
{
	if (!useFloatingThread) {
		StLock<Mutex> _(managerLock);
		ensureReadyThread();
	}
}

void MachServer::busy()
{
	StLock<Mutex> _(managerLock);
	idleCount--;
	if (useFloatingThread)
		ensureReadyThread();
}

void MachServer::idle()
{
	StLock<Mutex> _(managerLock);
	idleCount++;
}


void MachServer::ensureReadyThread()
{
	if (idleCount == 0) {
		if (workerCount >= maxWorkerCount) {
			this->threadLimitReached(workerCount);	// call remedial handler
		}
		if (workerCount < maxWorkerCount) { // threadLimit() may have raised maxWorkerCount
			(new LoadThread(*this))->threadRun();
		}
	}
}


//
// The callback hook for our subclasses.
// The default does nothing, thereby denying further thread creation.
// You could do something like maxThreads(limit+1) here to grant an variance;
// or throw an exception to avoid possible deadlocks (this would abort the current
// request but not otherwise impact the server's operation).
//
void MachServer::threadLimitReached(UInt32 limit)
{
}


//
// What our (non-primary) load threads do
//
void MachServer::LoadThread::threadAction()
{
	//@@@ race condition?! can server exit before helpers thread gets here?
	
	// register the worker thread and go
	server.addThread(this);
	try {
        secinfo("machserver", "start thread");
		server.runServerThread(true);
        secinfo("machserver", "end thread");
	} catch (...) {
		// fell out of server loop by error. Let the thread go quietly
        secinfo("machserver", "end thread (due to error)");
	}
	server.removeThread(this);
}


//
// Thread accounting
//
void MachServer::addThread(Thread *thread)
{
	StLock<Mutex> _(managerLock);
	workerCount++;
	idleCount++;
	workers.insert(thread);
}

void MachServer::removeThread(Thread *thread)
{
	StLock<Mutex> _(managerLock);
	workerCount--;
	idleCount--;
	workers.erase(thread);
    deadWorkers.insert(thread);
}

// Cleanup workers is a hack that make sure whe delete the object LoadThread
// that inheirit from Thread, this because there is no notification that the
// thread have completed.
//
// As I said, it a hack, but better then compeletely restructure how threads
// are brought up or replaced by XPC. Doing the XPC conversion should
// be done, because the current IPC mechanism doesn't handle that the server
// process dies and never comes back.

void MachServer::cleanupWorkers()
{
    StLock<Mutex> _(managerLock);
    while (!deadWorkers.empty()) {
        auto item = deadWorkers.begin();
        auto worker = *item;
        deadWorkers.erase(item);
        delete worker;
    }
}

//
// Timer management
//
MachServer::Timer::~Timer()
{ }

void MachServer::Timer::select()
{ }

void MachServer::Timer::unselect()
{ }

bool MachServer::processTimer()
{
	Timer *top;
	{	StLock<Mutex> _(managerLock);	// could have multiple threads trying this
		if (!(top = static_cast<Timer *>(timers.pop(Time::now()))))
			return false;				// nothing (more) to be done now
	}	// drop lock; work has been retrieved
	try {
        secinfo("machserver", "timer start: %p, %d, %f", top, top->longTerm(), Time::now().internalForm());
		StLock<MachServer::Timer,
			&MachServer::Timer::select, &MachServer::Timer::unselect> _t(*top);
		if (top->longTerm()) {
			StLock<MachServer, &MachServer::busy, &MachServer::idle> _(*this);
			top->action();
		} else {
			top->action();
		}
        secinfo("machserver", "timer end (false)");
	} catch (...) {
        secinfo("machserver", "timer end (true)");
	}
	return true;
}

void MachServer::setTimer(Timer *timer, Time::Absolute when)
{
	StLock<Mutex> _(managerLock);
	timers.schedule(timer, when); 
}
	
void MachServer::clearTimer(Timer *timer)
{
	StLock<Mutex> _(managerLock); 
	if (timer->scheduled())
		timers.unschedule(timer); 
}


//
// Notification hooks and shims. Defaults do nothing.
//
kern_return_t cdsa_mach_notify_dead_name(mach_port_t, mach_port_name_t port)
{
	try {
		MachServer::active().notifyDeadName(port);
	} catch (...) {
	}
    // the act of receiving a dead name notification allocates a dead-name
    // right that must be deallocated
    mach_port_deallocate(mach_task_self(), port);
	return KERN_SUCCESS;
}

void MachServer::notifyDeadName(Port) { }

kern_return_t cdsa_mach_notify_port_deleted(mach_port_t, mach_port_name_t port)
{
	try {
		MachServer::active().notifyPortDeleted(port);
	} catch (...) {
	}
	return KERN_SUCCESS;
}

void MachServer::notifyPortDeleted(Port) { }

kern_return_t cdsa_mach_notify_port_destroyed(mach_port_t, mach_port_name_t port)
{
	try {
		MachServer::active().notifyPortDestroyed(port);
	} catch (...) {
	}
	return KERN_SUCCESS;
}

void MachServer::notifyPortDestroyed(Port) { }

kern_return_t cdsa_mach_notify_send_once(mach_port_t port)
{
	try {
		MachServer::active().notifySendOnce(port);
	} catch (...) {
	}
	return KERN_SUCCESS;
}

void MachServer::notifySendOnce(Port) { }

kern_return_t cdsa_mach_notify_no_senders(mach_port_t port, mach_port_mscount_t count)
{
	try {
		MachServer::active().notifyNoSenders(port, count);
	} catch (...) {
	}
	return KERN_SUCCESS;
}

void MachServer::notifyNoSenders(Port, mach_port_mscount_t) { }

void MachServer::eventDone() { }


} // end namespace MachPlusPlus

} // end namespace Security
