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
// mach++ - C++ bindings for useful Mach primitives
//
#ifndef _H_MACHPP
#define _H_MACHPP

#include <security_utilities/utilities.h>
#include <security_utilities/errors.h>
#include <security_utilities/threading.h>
#include <security_utilities/globalizer.h>
#include <security_utilities/debugging_internal.h>
#include <mach/mach.h>
#include <bootstrap.h>
#include <set>

// yes, we use some UNIX (non-mach) headers...
#include <sys/types.h>
#include <unistd.h>

namespace Security {
namespace MachPlusPlus {


//
// Exceptions thrown by the mach++ interface.
//
class Error : public CommonError {
protected:
	// actually, kern_return_t can be just about any subsystem type return code
	Error(kern_return_t err);
public:
	virtual ~Error() _NOEXCEPT;

    virtual OSStatus osStatus() const;
	virtual int unixError() const;

	const kern_return_t error;
	
	static void check(kern_return_t err);
    static void throwMe(kern_return_t err) __attribute__((noreturn));
};

// generic return code checker
inline void check(kern_return_t status)
{ Error::check(status); }


//
// Simple vm_allocate/deallocate glue
//
void *allocate(size_t size);
void deallocate(vm_address_t addr, size_t size);

inline void deallocate(const void *addr, size_t size)
{ deallocate(reinterpret_cast<vm_address_t>(addr), size); }


//
// An encapsulation of a Mach 3 port
//
class Port {
protected:
	static mach_port_t self() { return mach_task_self(); }	

public:
	Port() { mPort = MACH_PORT_NULL; }
	Port(mach_port_t port) { mPort = port; }
	
	// devolve to Mach primitive type
	operator mach_port_t () const	{ return mPort; }

	// access reference (for primitives storing into &mach_port_t)
	mach_port_t &port ()			{ return mPort; }
	const mach_port_t &port () const { return mPort; }
	
	// status checks
	mach_port_type_t type() const
	{ mach_port_type_t typ; check(mach_port_type(self(), mPort, &typ)); return typ; }
	
	bool isType(mach_port_type_t typ) const	{ return type() & typ; }
	bool isDead() const		{ return isType(MACH_PORT_TYPE_DEAD_NAME); }

	// port allocation and management
	void allocate(mach_port_right_t right = MACH_PORT_RIGHT_RECEIVE)
	{ check(mach_port_allocate(self(), right, &mPort)); }
	/*
	 * (╯ರ ~ ರ）╯︵ ┻━┻
	 * mach_port_deallocate() only deallocates send, send-once, dead-name, or port-set.
	 * Since allocate() defaults to receive, allocate() and deallocate() do not actually
	 * balance each other; deallocate() will fail with an invalid-right error.
	 */
	void deallocate()	{ check(mach_port_deallocate(self(), mPort)); mPort = MACH_PORT_NULL;}
	
	void insertRight(mach_msg_type_name_t type)
	{ check(mach_port_insert_right(self(), mPort, mPort, type)); }
	
	void modRefs(mach_port_right_t right, mach_port_delta_t delta = 1)
	{ check(mach_port_mod_refs(self(), mPort, right, delta)); }
	
	mach_port_urefs_t getRefs(mach_port_right_t right);

	// port notification interface
	mach_port_t requestNotify(mach_port_t notify,
		mach_msg_id_t type = MACH_NOTIFY_DEAD_NAME, mach_port_mscount_t sync = 1);
    mach_port_t cancelNotify(mach_msg_id_t type = MACH_NOTIFY_DEAD_NAME);

	// queue state management
	mach_port_msgcount_t qlimit() const;
	void qlimit(mach_port_msgcount_t limit);
	
    IFDUMP(void dump(const char *name = NULL));
	
protected:
	mach_port_t mPort;
};


//
// Ports representing PortSets
//
class PortSet : public Port {
public:
	PortSet() { allocate(MACH_PORT_RIGHT_PORT_SET); }
	~PortSet() { deallocate(); }
	
	void operator += (const Port &port)
	{ check(mach_port_move_member(self(), port, mPort)); }
    
    void operator -= (const Port &port)
    { check(mach_port_move_member(self(), port, MACH_PORT_NULL)); }
	
	set<Port> members() const;
	bool contains(Port member) const;	// relatively slow
};


//
// Ports that are bootstrap ports
//
class Bootstrap : public Port {
public:
    Bootstrap() { check(task_get_bootstrap_port(mach_task_self(), &mPort)); }
    Bootstrap(mach_port_t bootp) : Port(bootp) { }

	mach_port_t checkInOptional(const char *name) const;
    
	void registerAs(mach_port_t port, const char *name) const;
    
	mach_port_t lookup2(const char *name) const;

    IFDUMP(void dump());
	
private:
	// officially, the register/lookup IPCs take an array of 128 characters (not a zero-end string)
	mutable char nameBuffer[BOOTSTRAP_MAX_NAME_LEN];
    
protected:
	char *makeName(const char *s) const
	{ return strncpy(nameBuffer, s, BOOTSTRAP_MAX_NAME_LEN); }
};


//
// Ports that are Task Ports or Task Name Ports
// The only added functionality is pid_for_task, which works on either.
//
class TaskPort : public Port {
public:
    TaskPort() { mPort = self(); }
    TaskPort(mach_port_t p) : Port(p) { }
    
    pid_t pid() const;
};


//
// Ports that are are self-allocated and have receive rights
//
class ReceivePort : public Port {
public:
	ReceivePort()	{ allocate(); }
	ReceivePort(const char *name, const Bootstrap &bootstrap, bool tryCheckin = true);
	~ReceivePort()	{ modRefs(MACH_PORT_RIGHT_RECEIVE, -1); }
};


class ReplyPort : public Port {
public:
    ReplyPort() {
        mach_port_options_t opts = {
            .flags = MPO_PROVISIONAL_REPLY_PORT,
        };
        check(mach_port_construct(self(), &opts, 0, &mPort));
    }

    ~ReplyPort() {
        check(mach_port_destruct(self(), mPort, 0, 0));
        mPort = MACH_PORT_NULL;
    }
};


//
// A Mach-level memory guard.
// This will vm_deallocate its argument when it gets destroyed.
//
class VMGuard {
public:
	VMGuard(void *addr, size_t length) : mAddr(addr), mLength(length) { }
	~VMGuard()	{ deallocate(mAddr, mLength); }

private:
	void *mAddr;
	size_t mLength;
};


//
// Message buffers for Mach messages.
// The logic here is somewhat inverted from the usual: send/receive
// are methods on the buffers (rather than buffers being arguments to send/receive).
// It's rather handy once you get used to that view.
//
class Message {
public:
    Message(void *buffer, mach_msg_size_t size);		// use buffer with size
    Message(mach_msg_size_t size);					// allocate buffer with size
    Message();								// set buffer later
    virtual ~Message();
	
    void setBuffer(void *buffer, mach_msg_size_t size); // use buffer with size
    void setBuffer(mach_msg_size_t size);			// allocate buffer with size
    void clearBuffer(void);
    void release();							// discard buffer (if any)

    operator mig_reply_error_t & () const	{ return *mBuffer; }
    operator mach_msg_header_t & () const	{ return mBuffer->Head; }
    operator mig_reply_error_t * () const	{ return mBuffer; }
    operator mach_msg_header_t * () const	{ return &mBuffer->Head; }
    operator NDR_record_t & () const		{ return mBuffer->NDR; }
    
    void *data() const						{ return mBuffer; }
    mach_msg_size_t length() const			{ return mBuffer->Head.msgh_size; }
    Port localPort() const					{ return mBuffer->Head.msgh_local_port; }
    Port remotePort() const					{ return mBuffer->Head.msgh_remote_port; }
    mach_msg_id_t msgId() const				{ return mBuffer->Head.msgh_id; }
    mach_msg_bits_t bits() const			{ return mBuffer->Head.msgh_bits; }
    kern_return_t returnCode() const		{ return mBuffer->RetCode; }
    mach_msg_audit_trailer_t *auditTrailer();
    
    void localPort(mach_port_t p)			{ mBuffer->Head.msgh_local_port = p; }
    void remotePort(mach_port_t p)			{ mBuffer->Head.msgh_remote_port = p; }
    
public:
    bool send(mach_msg_option_t options = 0,
        mach_msg_timeout_t timeout = MACH_MSG_TIMEOUT_NONE,
        mach_port_name_t notify = MACH_PORT_NULL);
    bool receive(mach_port_t receivePort,
        mach_msg_option_t options = 0,
        mach_msg_timeout_t timeout = MACH_MSG_TIMEOUT_NONE,
        mach_port_name_t notify = MACH_PORT_NULL);
    bool sendReceive(mach_port_t receivePort,
        mach_msg_option_t options = 0,
        mach_msg_timeout_t timeout = MACH_MSG_TIMEOUT_NONE,
        mach_port_name_t notify = MACH_PORT_NULL);
    
    void destroy()		{ mach_msg_destroy(*this); }
    
protected:
    bool check(kern_return_t status);

private:
    mig_reply_error_t *mBuffer;
    mach_msg_size_t mSize;
    bool mRelease;
};


} // end namespace MachPlusPlus
} // end namespace Security

#endif //_H_MACHPP
