/*
 * Copyright (c) 2000-2009 Apple Inc. All Rights Reserved.
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
// process - track a single client process and its belongings
//
#ifndef _H_PROCESS
#define _H_PROCESS

#include "structure.h"
#include "session.h"
#include <security_utilities/refcount.h>
#include <security_utilities/ccaudit.h>
#include "clientid.h"
#include "localkey.h"
#include "notifications.h"
#include <string>

using MachPlusPlus::Port;
using MachPlusPlus::TaskPort;
using MachPlusPlus::Bootstrap;

class Session;
class LocalDatabase;
class AuthorizationToken;


//
// A Process object represents a UNIX process (and associated Mach Task) that has
// had contact with us and may have some state associated with it. It primarily tracks
// the process nature of the client. Individual threads in the client are tracked by
// Connection objects.
//
// ClientIdentification tracks the identity of guests in the client *as securityd clients*.
// It is concerned with which guest is asking for securityd services, and whether this
// should be granted.
//
class Process : public PerProcess,
				public ClientIdentification{
public:
	Process(TaskPort tPort, Bootstrap bootstrapPort, const ClientSetupInfo *info, const CommonCriteria::AuditToken &audit);
	virtual ~Process();
	
	void reset(TaskPort tPort, const ClientSetupInfo *info, const CommonCriteria::AuditToken &audit);
    
    uid_t uid() const			{ return mUid; }
    gid_t gid() const			{ return mGid; }
    pid_t pid() const			{ return mPid; }
    Security::CommonCriteria::AuditToken const &audit_token() const { return mAudit; }
    TaskPort taskPort() const	{ return mTaskPort; }
    Bootstrap bootstrap() const	{ return mBootstrap; }
	bool byteFlipped() const	{ return mByteFlipped; }
	
	using PerProcess::kill;
	void kill();
	
	void changeSession(Session::SessionId sessionId);
    
	Session& session() const;
	void checkSession(const audit_token_t &auditToken);
	
	LocalDatabase &localStore();
	Key *makeTemporaryKey(const CssmKey &key, CSSM_KEYATTR_FLAGS moreAttributes,
		const AclEntryPrototype *owner);

	// aclSequence is taken to serialize ACL validations to pick up mutual changes
	Mutex aclSequence;

    // Dumping is buggy and only hurts debugging. It's dead Jim.
	//IFDUMP(void dumpNode());
	
private:
	void setup(const ClientSetupInfo *info);
	
private:
	// peer state: established during connection startup; fixed thereafter
    TaskPort mTaskPort;					// task name port
    Bootstrap mBootstrap;				// bootstrap port
	bool mByteFlipped;					// client's byte order is reverse of ours
    pid_t mPid;							// process id
    uid_t mUid;							// UNIX uid credential
    gid_t mGid;							// primary UNIX gid credential

    Security::CommonCriteria::AuditToken const mAudit; // audit token

	// canonical local (transient) key store
	RefPointer<LocalDatabase> mLocalStore;
};


//
// Convenience comparison
//
inline bool operator == (const Process &p1, const Process &p2)
{
	return &p1 == &p2;
}


#endif //_H_PROCESS
