/*
 * Copyright (c) 2000-2008,2011,2013 Apple Inc. All Rights Reserved.
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
// ssclient - SecurityServer client interface library
//
#include "sstransit.h"
#include "ucsp.h"
#include <os/assumes.h>
#include <servers/netname.h>
#include <security_utilities/debugging.h>

using MachPlusPlus::check;
using MachPlusPlus::Bootstrap;


namespace Security {
namespace SecurityServer {


//
// The process-global object
//
UnixPlusPlus::StaticForkMonitor ClientSession::mHasForked;
ModuleNexus<ClientSession::Global> ClientSession::mGlobal;
const char *ClientSession::mContactName;


//
// Construct a client session
//
ClientSession::ClientSession(Allocator &std, Allocator &rtn)
: ClientCommon(std, rtn), mCallback(NULL), mCallbackContext(NULL)
{ }


//
// Destroy a session
//
ClientSession::~ClientSession()
{ }


void
ClientSession::registerForAclEdits(DidChangeKeyAclCallback *callback, void *context)
{
	mCallback = callback;
	mCallbackContext = context;
}

// chroot safety: revert to old behavior on old kernel
static task_id_token_t
self_token_create(void)
{
    task_id_token_t self_token = TASK_ID_TOKEN_NULL;

    kern_return_t kr = task_create_identity_token(mach_task_self(), &self_token);
    if (kr == MIG_BAD_ID) {
        self_token = mach_task_self();
    } else {
        os_assert_zero(kr);
    }

    return self_token;
}

// chroot safety: self_token_create may have returned the task port
static void
self_token_deallocate(task_id_token_t token)
{
    if (token != mach_task_self()) {
        (void)mach_port_deallocate(mach_task_self(), token);
    }
}

//
// Perform any preambles required to be a securityd client in good standing.
// This includes initial setup calls, thread registration, fork management,
// and (Code Signing) guest status.
//
void ClientSession::activate()
{
	// Guard against fork-without-exec. If we are the child of a fork
	// (that has not exec'ed), our apparent connection to SecurityServer
	// is just a mirage, and we better reset it.
	if (mHasForked()) {
		secinfo("SSclnt", "process has forked (now pid=%d) - resetting connection object", getpid());
		mGlobal.reset();
	}
		
	// now pick up the (new or existing) connection state
	Global &global = mGlobal();
    Thread &thread = global.thread();
    if (!thread) {
        // first time for this thread - use abbreviated registration
        try {
            mach_port_t bsport = MACH_PORT_NULL;
            (void)os_assumes_zero(task_get_bootstrap_port(mach_task_self(), &bsport));
            IPCN(ucsp_client_setupThreadWithBootstrap(UCSP_ARGS, bsport));
            (void)os_assumes_zero(mach_port_deallocate(mach_task_self(), bsport));
        } catch (const MachPlusPlus::Error &err) {
            if (err.error != MIG_BAD_ID) {
                throw;
            }

            task_id_token_t token = self_token_create();
            IPCN(ucsp_client_setupThread(UCSP_ARGS, token));
            self_token_deallocate(token);
        }
        thread.registered = true;
        secinfo("SSclnt", "Thread registered with %s", mContactName);
	}
	
}

//
// The contactName method allows the caller to explicitly override the bootstrap
// name under which SecurityServer is located. Use this only with great caution,
// and probably only for debugging.
// Note that no explicit locking is done here. It is the caller's responsibility
// to make sure this is called from thread-safe context before the real dance begins.
//
void ClientSession::contactName(const char *name)
{
	mContactName = name;
}

const char *ClientSession::contactName() const
{
	return mContactName;
}


//
// Construct the process-global state object.
// The ModuleNexus construction magic will ensure that this happens uniquely
// even if the face of multithreaded attack.
//
ClientSession::Global::Global()
{
    // find server port
	serverPort = findSecurityd();
    
	mach_port_t originPort = MACH_PORT_NULL;
	ReplyPort verifyReplyPort;
	IPCBASIC(ucsp_client_verifyPrivileged2(serverPort.port(), verifyReplyPort, &securitydCreds, &rcode, &originPort));
	if (originPort != serverPort.port())
		CssmError::throwMe(CSSM_ERRCODE_VERIFICATION_FAILURE);
	mach_port_mod_refs(mach_task_self(), originPort, MACH_PORT_RIGHT_SEND, -1);
	
    // send identification/setup message
	static const char extForm[] = "?:obsolete";
	ClientSetupInfo info = { 0x1234, SSPROTOVERSION };
	
    // cannot use UCSP_ARGS here because it uses mGlobal() -> deadlock
    Thread &thread = this->thread();

    try {
        mach_port_t bsport = MACH_PORT_NULL;
        (void)os_assumes_zero(task_get_bootstrap_port(mach_task_self(), &bsport));
        IPCBASIC(ucsp_client_setupWithBootstrap(serverPort, thread.replyPort, &securitydCreds, &rcode,
            bsport, info, extForm));
        (void)os_assumes_zero(mach_port_deallocate(mach_task_self(), bsport));
    } catch (const MachPlusPlus::Error &err) {
        if (err.error != MIG_BAD_ID) {
            throw;
        }

        task_id_token_t token = self_token_create();
        IPCBASIC(ucsp_client_setup(serverPort, thread.replyPort, &securitydCreds, &rcode,
            token, info, extForm));
        self_token_deallocate(token);
    }
    thread.registered = true;	// as a side-effect of setup call above
	IFDEBUG(serverPort.requestNotify(thread.replyPort));
	secinfo("SSclnt", "contact with %s established", mContactName);
}


//
// Reset the connection.
// This discards all client state accumulated for the securityd link.
// Existing connections will go stale and fail; new connections will
// re-establish the link. This is an expert tool ONLY. If you don't know
// exactly how this gig is danced, you don't want to call this. Really.
//
void ClientSession::reset()
{
	secinfo("SSclnt", "resetting client state (OUCH)");
	mGlobal.reset();
}


//
// Common utility for finding the registered securityd port for the current
// session. This does not cache the port anywhere, though it does effectively
// cache the name.
//
Port ClientSession::findSecurityd()
{
	if (!mContactName)
	{
		mContactName = SECURITYSERVER_BOOTSTRAP_NAME;
	}

    secinfo("SSclnt", "Locating %s", mContactName);
    Port serverPort = Bootstrap().lookup2(mContactName);
	secinfo("SSclnt", "contacting %s at port %d (version %d)",
		mContactName, serverPort.port(), SSPROTOVERSION);
	return serverPort;
}


//
// Subsidiary process management.
// This does not go through the generic securityd-client setup.
//
void ClientSession::childCheckIn(Port serverPort, Port taskPort)
{
	Port securitydPort = findSecurityd();
	mach_port_t originPort = MACH_PORT_NULL;
	ReplyPort verifyReplyPort;
	IPCN(ucsp_client_verifyPrivileged2(securitydPort.port(), verifyReplyPort, &securitydCreds, &rcode, &originPort));
	if (originPort != securitydPort.port())
		CssmError::throwMe(CSSM_ERRCODE_VERIFICATION_FAILURE);
	mach_port_mod_refs(mach_task_self(), originPort, MACH_PORT_RIGHT_SEND, -1);
	check(ucsp_client_childCheckIn(securitydPort, serverPort, MACH_PORT_NULL));
}


//
// Notify an (interested) caller that a securityd-mediated ACL change
// MAY have happened on a key object involved in an operation. This allows
// such callers to re-encode key blobs for storage.
//
void ClientSession::notifyAclChange(KeyHandle key, CSSM_ACL_AUTHORIZATION_TAG tag)
{
	if (mCallback) {
		secinfo("keyacl", "ACL change key %u operation %u", key, tag);
		mCallback(mCallbackContext, *this, key, tag);
	} else
		secinfo("keyacl", "dropped ACL change notice for key %u operation %u",
			key, tag);
}


} // end namespace SecurityServer
} // end namespace Security
