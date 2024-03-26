/*
 * Copyright (c) 2000-2009,2012-2013,2016 Apple Inc. All Rights Reserved.
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
// transition - securityd IPC-to-class-methods transition layer
//
// This file contains all server-side MIG implementations for the main
// securityd protocol ("ucsp"). It dispatches them into the vast object
// conspiracy that is securityd, anchored in the Server object.
//
#include <securityd_client/ss_types.h>
#include "server.h"
#include "session.h"
#include "agentquery.h"
#include "database.h"
#include "kcdatabase.h"
#include "tokendatabase.h"
#include "acl_keychain.h"
#include "kckey.h"
#include "child.h"
#include <syslog.h>
#include <mach/mach_error.h>
#include "SecRandom.h"
#include <securityd_client/xdr_cssm.h>
#include <securityd_client/xdr_auth.h>
#include <securityd_client/xdr_dldb.h>
#include <security_utilities/logging.h>
#include <security_utilities/casts.h>
#include <Security/AuthorizationTagsPriv.h>
#define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#include <AssertMacros.h>
#include <security_utilities/errors.h>
#include <security_utilities/mach++.h>
#include <Security/SecEntitlements.h>

#include <CoreFoundation/CFNumber.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFPropertyList.h>

#define mig_external extern "C"
#include "ucspServer.h"
#undef mig_external

//
// Bracket Macros
//
#define UCSP_ARGS	mach_port_t servicePort, mach_port_t replyPort, \
	audit_token_t auditToken, CSSM_RETURN *rcode

#define BEGIN_IPCN	*rcode = CSSM_OK; try {
#define BEGIN_IPC(name)	BEGIN_IPCN RefPointer<Connection> connRef(&Server::connection(replyPort, auditToken)); \
		Connection &connection __attribute__((unused)) = *connRef; \
        secinfo("SecServer", "request entry " #name " (pid:%d session:%d)", connection.process().pid(), connection.session().sessionId());

#define END_IPC(base)	END_IPCN(base) Server::requestComplete(*rcode); return KERN_SUCCESS;
#define END_IPCN(base) 	secinfo("SecServer", "request return: %d", *(rcode)); \
	} \
	catch (const CommonError &err) { *rcode = CssmError::cssmError(err, CSSM_ ## base ## _BASE_ERROR); } \
	catch (const std::bad_alloc &) { *rcode = CssmError::merge(CSSM_ERRCODE_MEMORY_ERROR, CSSM_ ## base ## _BASE_ERROR); } \
	catch (Connection *conn) { *rcode = 0; } \
	catch (...) { *rcode = CssmError::merge(CSSM_ERRCODE_INTERNAL_ERROR, CSSM_ ## base ## _BASE_ERROR); }

#define BEGIN_IPCS		try {
#define	END_IPCS(more)	} catch (...) { } \
						mach_port_deallocate(mach_task_self(), servicePort); more; return KERN_SUCCESS;

#define DATA_IN(base)	void *base, mach_msg_type_number_t base##Length
#define DATA_OUT(base)	void **base, mach_msg_type_number_t *base##Length
#define DATA(base)		CssmData(base, base##Length)

#define SSBLOB(Type, name) makeBlob<Type>(DATA(name))

using LowLevelMemoryUtilities::increment;
using LowLevelMemoryUtilities::difference;

class CopyOutAccessCredentials : public CopyOut {
public:
	CopyOutAccessCredentials(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_ACCESS_CREDENTIALS), reinterpret_cast<xdrproc_t>(xdr_CSSM_ACCESS_CREDENTIALS_PTR)) { }
	operator AccessCredentials *() { return static_cast<AccessCredentials *>(reinterpret_cast<CSSM_ACCESS_CREDENTIALS_PTR>(data())); }
};


class CopyOutEntryAcl : public CopyOut {
public:
	CopyOutEntryAcl(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_ACL_ENTRY_PROTOTYPE), reinterpret_cast<xdrproc_t>(xdr_CSSM_ACL_ENTRY_PROTOTYPE_PTR)) { }
	operator AclEntryPrototype *() { return static_cast<AclEntryPrototype *>(reinterpret_cast<CSSM_ACL_ENTRY_PROTOTYPE_PTR>(data())); }
};

class CopyOutOwnerAcl : public CopyOut {
public:
	CopyOutOwnerAcl(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_ACL_OWNER_PROTOTYPE), reinterpret_cast<xdrproc_t>(xdr_CSSM_ACL_OWNER_PROTOTYPE_PTR)) { }
	operator AclOwnerPrototype *() { return static_cast<AclOwnerPrototype *>(reinterpret_cast<CSSM_ACL_OWNER_PROTOTYPE_PTR>(data())); }
};

class CopyOutAclEntryInput : public CopyOut {
public:
	CopyOutAclEntryInput(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_ACL_ENTRY_INPUT), reinterpret_cast<xdrproc_t>(xdr_CSSM_ACL_ENTRY_INPUT_PTR)) { }
	operator AclEntryInput *() { return static_cast<AclEntryInput *>(reinterpret_cast<CSSM_ACL_ENTRY_INPUT_PTR>(data())); }
};


class CopyOutDeriveData : public CopyOut {
public:
	CopyOutDeriveData(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_DERIVE_DATA), reinterpret_cast<xdrproc_t>(xdr_CSSM_DERIVE_DATA_PTR)) { }
	CSSM_DERIVE_DATA * derive_data() { return reinterpret_cast<CSSM_DERIVE_DATA *>(data()); }
	CSSM_DATA &cssm_data() { return derive_data()->baseData; }
	CSSM_ALGORITHMS algorithm() { return derive_data()->algorithm; }
};


class CopyOutContext : public CopyOut {
public:
	CopyOutContext(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_CONTEXT), reinterpret_cast<xdrproc_t>(xdr_CSSM_CONTEXT_PTR)) { }
	operator Context *() { return static_cast<Context *>(reinterpret_cast<CSSM_CONTEXT_PTR>(data())); }
	Context &context() { return *static_cast<Context *>(reinterpret_cast<CSSM_CONTEXT_PTR>(data())); }
};

class CopyOutKey : public CopyOut {
public:
	CopyOutKey(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_KEY), reinterpret_cast<xdrproc_t>(xdr_CSSM_KEY_PTR)) { }
	operator CssmKey *() { return static_cast<CssmKey *>(reinterpret_cast<CSSM_KEY_PTR>(data())); }
	CssmKey &key() { return *static_cast<CssmKey *>(reinterpret_cast<CSSM_KEY_PTR>(data())); }
};

class CopyOutDbRecordAttributes : public CopyOut {
public:
	CopyOutDbRecordAttributes(void *copy, size_t size) : CopyOut(copy, size + sizeof(CSSM_DB_RECORD_ATTRIBUTE_DATA), reinterpret_cast<xdrproc_t>(xdr_CSSM_DB_RECORD_ATTRIBUTE_DATA_PTR)) { }
	CssmDbRecordAttributeData *attribute_data() { return static_cast<CssmDbRecordAttributeData *>(reinterpret_cast<CSSM_DB_RECORD_ATTRIBUTE_DATA_PTR>(data())); }
};

class CopyOutQuery : public CopyOut {
public:
	CopyOutQuery(void *copy, size_t size) : CopyOut(copy, size, reinterpret_cast<xdrproc_t>(xdr_CSSM_QUERY_PTR)) { }
	operator CssmQuery *() { return static_cast<CssmQuery *>(reinterpret_cast<CSSM_QUERY_PTR>(data())); }
};

//
// Take a DATA type RPC argument purportedly representing a Blob of some kind,
// turn it into a Blob, and fail properly if it's not kosher.
//
template <class BlobType>
const BlobType *makeBlob(const CssmData &blobData, CSSM_RETURN error = CSSM_ERRCODE_INVALID_DATA)
{
	if (!blobData.data() || blobData.length() < sizeof(BlobType))
		CssmError::throwMe(error);
	const BlobType *blob = static_cast<const BlobType *>(blobData.data());
	if (blob->totalLength != blobData.length())
		CssmError::throwMe(error);
	return blob;
}

//
// An OutputData object will take memory allocated within securityd,
// hand it to the MIG return-output parameters, and schedule it to be released
// after the MIG reply has been sent. It will also get rid of it in case of
// error.
//
class OutputData : public CssmData {
public:
	OutputData(void **outP, mach_msg_type_number_t *outLength)
		: mData(*outP), mLength(*outLength) { }
	~OutputData()
	{ mData = data(); mLength = int_cast<size_t, mach_msg_type_number_t>(length()); Server::releaseWhenDone(mData); }

    void operator = (const CssmData &source)
    { CssmData::operator = (source); }

private:
	void * &mData;
	mach_msg_type_number_t &mLength;
};

//
// Choose a Database from a choice of two sources, giving preference
// to persistent stores and to earlier sources.
//
Database *pickDb(Database *db1, Database *db2);

static inline Database *dbOf(Key *key)	{ return key ? &key->database() : NULL; }

inline Database *pickDb(Key *k1, Key *k2) { return pickDb(dbOf(k1), dbOf(k2)); }
inline Database *pickDb(Database *db1, Key *k2) { return pickDb(db1, dbOf(k2)); }
inline Database *pickDb(Key *k1, Database *db2) { return pickDb(dbOf(k1), db2); }

//
// Choose a Database from a choice of two sources, giving preference
// to persistent stores and to earlier sources.
//
Database *pickDb(Database *db1, Database *db2)
{
	// persistent db1 always wins
	if (db1 && !db1->transient())
		return db1;

	// persistent db2 is next choice
	if (db2 && !db2->transient())
		return db2;

	// pick any existing transient database
	if (db1)
		return db1;
	if (db2)
		return db2;

	// none at all. use the canonical transient store
	return Server::optionalDatabase(noDb);
}

static void checkPathLength(char const *str) {
    if (strlen(str) >= PATH_MAX) {
        secerror("SecServer: path too long");
        CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
    }
}

//
// Setup/Teardown functions.
//

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-prototypes"

kern_return_t
ucsp_server_setupWithBootstrap(UCSP_ARGS, mach_port_t bootstrap, ClientSetupInfo info, const char *identity)
{
    mach_port_t taskName = MACH_PORT_NULL;
    secinfo("SecServer", "request entry: setupWithBootstrap");
    BEGIN_IPCN
    kern_return_t kr = task_name_for_pid(mach_task_self(), audit_token_to_pid(auditToken), &taskName);
    MachPlusPlus::check(kr);
    Server::active().setupConnection(Server::connectNewProcess, replyPort,
        taskName, bootstrap, auditToken, &info);
    END_IPCN(CSSM)
    if (*rcode) {
        Syslog::notice("setupWithBootstrap(%s) failed rcode=%d", identity ? identity : "<NULL>", *rcode);
    }
    mach_port_deallocate(mach_task_self(), taskName);
    mach_port_deallocate(mach_task_self(), bootstrap);
    return KERN_SUCCESS;
}

kern_return_t
ucsp_server_setupThreadWithBootstrap(UCSP_ARGS, mach_port_t bootstrap)
{
    mach_port_t taskName = MACH_PORT_NULL;
    secinfo("SecServer", "request entry: setupThreadWithBootstrap");
    BEGIN_IPCN
    kern_return_t kr = task_name_for_pid(mach_task_self(), audit_token_to_pid(auditToken), &taskName);
    MachPlusPlus::check(kr);
    Server::active().setupConnection(Server::connectNewThread, replyPort, taskName, bootstrap, auditToken);
    END_IPCN(CSSM)
    if (*rcode) {
        Syslog::notice("setupThreadWithBootstrap failed rcode=%d", *rcode);
    }
    mach_port_deallocate(mach_task_self(), taskName);
    mach_port_deallocate(mach_task_self(), bootstrap);
    return KERN_SUCCESS;
}

kern_return_t ucsp_server_verifyPrivileged(UCSP_ARGS)
{
	BEGIN_IPCN
    secinfo("SecServer", "request entry: verifyPrivileged");
	// doing nothing (we just want securityd's audit credentials returned)
	END_IPCN(CSSM)
	return KERN_SUCCESS;
}

kern_return_t ucsp_server_verifyPrivileged2(UCSP_ARGS, mach_port_t *originPort)
{
	BEGIN_IPCN

    secinfo("SecServer", "request entry: verifyPrivileged2");
	// send the port back to the sender to check for a MitM (6986198)
	*originPort = servicePort;
	END_IPCN(CSSM)
	return KERN_SUCCESS;
}

//
// Common database operations
//
kern_return_t ucsp_server_authenticateDb(UCSP_ARGS, DbHandle db,
	CSSM_DB_ACCESS_TYPE accessType, DATA_IN(cred))
{
	BEGIN_IPC(authenticateDb)
    secinfo("dl", "authenticateDb");
	CopyOutAccessCredentials creds(cred, credLength);
	// ignoring accessType
    Server::database(db)->authenticate(accessType, creds);
	END_IPC(DL)
}

kern_return_t ucsp_server_releaseDb(UCSP_ARGS, DbHandle db)
{
	BEGIN_IPC(releaseDb)
	connection.process().kill(*Server::database(db));
	END_IPC(DL)
}


kern_return_t ucsp_server_getDbName(UCSP_ARGS, DbHandle db, char name[PATH_MAX])
{
	BEGIN_IPC(getDbName)
	string result = Server::database(db)->dbName();
    checkPathLength(result.c_str());
    memcpy(name, result.c_str(), result.length() + 1);
	END_IPC(DL)
}

kern_return_t ucsp_server_setDbName(UCSP_ARGS, DbHandle db, const char *name)
{
	BEGIN_IPC(setDbName)
    checkPathLength(name);
    Server::database(db)->dbName(name);
	END_IPC(DL)
}


//
// External database interface
//
kern_return_t ucsp_server_openToken(UCSP_ARGS, uint32 ssid, FilePath name,
	DATA_IN(accessCredentials), DbHandle *db)
{
	BEGIN_IPC(openToken)
	CopyOutAccessCredentials creds(accessCredentials, accessCredentialsLength);
// The static analyzer is not a fan of this "create object, send handle to foreign process" model. Tell it not to worry.
#ifndef __clang_analyzer__
	*db = (new TokenDatabase(ssid, connection.process(), name, creds))->handle();
#endif
	END_IPC(DL)
}

kern_return_t ucsp_server_findFirst(UCSP_ARGS, DbHandle db,
	DATA_IN(inQuery), DATA_IN(inAttributes), DATA_OUT(outAttributes),
	boolean_t getData, DATA_OUT(data),
    KeyHandle *hKey, SearchHandle *hSearch, IPCRecordHandle *hRecord)
{
	BEGIN_IPC(findFirst)
	CopyOutQuery query(inQuery, inQueryLength);
	CopyOutDbRecordAttributes attrs(inAttributes, inAttributesLength);

	RefPointer<Database::Search> search;
	RefPointer<Database::Record> record;
	RefPointer<Key> key;
	CssmData outData;
	CssmDbRecordAttributeData *outAttrs = NULL; mach_msg_type_number_t outAttrsLength;
	Server::database(db)->findFirst(*query,
        attrs.attribute_data(), attrs.length(),
		getData ? &outData : NULL, key, search, record, outAttrs, outAttrsLength);

	// handle nothing-found case without exceptions
	if (!record) {
		*hRecord = noRecord;
		*hSearch = noSearch;
		*hKey = noKey;
	} else {
		// return handles
		*hRecord = record->handle();
		*hSearch = search->handle();
		*hKey = key ? key->handle() : noKey;

        if (outAttrsLength && outAttrs) {
            Server::releaseWhenDone(outAttrs); // exception proof it against next line
            if (!copyin(outAttrs, reinterpret_cast<xdrproc_t> (xdr_CSSM_DB_RECORD_ATTRIBUTE_DATA), outAttributes, outAttributesLength))
                CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
            Server::releaseWhenDone(*outAttributes);
        }

		// return data (temporary fix)
		if (getData) {
			Server::releaseWhenDone(outData.data());
            xdrproc_t encode_proc = reinterpret_cast<xdrproc_t>(xdr_CSSM_NO_KEY_IN_DATA);
            if (key)
                encode_proc = reinterpret_cast<xdrproc_t>(xdr_CSSM_KEY_IN_DATA);
			if (!copyin(&outData, encode_proc, data, dataLength))
				CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
			Server::releaseWhenDone(*data);
		}
	}
	END_IPC(DL)
}


kern_return_t ucsp_server_findNext(UCSP_ARGS, SearchHandle hSearch,
	DATA_IN(inAttributes),
	DATA_OUT(outAttributes),
	boolean_t getData, DATA_OUT(data), KeyHandle *hKey,
	IPCRecordHandle *hRecord)
{
	BEGIN_IPC(findNext)
	CopyOutDbRecordAttributes attrs(inAttributes, inAttributesLength);
	RefPointer<Database::Search> search =
		Server::find<Database::Search>(hSearch, CSSMERR_DL_INVALID_RESULTS_HANDLE);
	RefPointer<Database::Record> record;
	RefPointer<Key> key;
	CssmData outData;
	CssmDbRecordAttributeData *outAttrs = NULL; mach_msg_type_number_t outAttrsLength;
	search->database().findNext(search, attrs.attribute_data(), attrs.length(),
		getData ? &outData : NULL, key, record, outAttrs, outAttrsLength);

	// handle nothing-found case without exceptions
	if (!record) {
		*hRecord = noRecord;
		*hKey = noKey;
	} else {
		// return handles
		*hRecord = record->handle();
		*hKey = key ? key->handle() : noKey;

        if (outAttrsLength && outAttrs) {
			secinfo("attrmem", "Found attrs: %p of length: %d", outAttrs, outAttrsLength);
            Server::releaseWhenDone(outAttrs); // exception proof it against next line
            if (!copyin(outAttrs, reinterpret_cast<xdrproc_t> (xdr_CSSM_DB_RECORD_ATTRIBUTE_DATA), outAttributes, outAttributesLength))
                CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
			secinfo("attrmem", "Copied attrs: %p of length: %d", *outAttributes, *outAttributesLength);
            Server::releaseWhenDone(*outAttributes);
        }

		// return data (temporary fix)
		if (getData) {
			Server::releaseWhenDone(outData.data());
            xdrproc_t encode_proc = reinterpret_cast<xdrproc_t>(xdr_CSSM_NO_KEY_IN_DATA);
            if (key)
                encode_proc = reinterpret_cast<xdrproc_t>(xdr_CSSM_KEY_IN_DATA);
            if (!copyin(&outData, encode_proc, data, dataLength))
                CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
			Server::releaseWhenDone(*data);
		}
	}
	END_IPC(DL)
}

kern_return_t ucsp_server_findRecordHandle(UCSP_ARGS, IPCRecordHandle hRecord,
	DATA_IN(inAttributes), DATA_OUT(outAttributes),
	boolean_t getData, DATA_OUT(data), KeyHandle *hKey)
{
	BEGIN_IPC(findRecordHandle)
	CopyOutDbRecordAttributes attrs(inAttributes, inAttributesLength);
	RefPointer<Database::Record> record =
		Server::find<Database::Record>(hRecord, CSSMERR_DL_INVALID_RECORD_UID);
	RefPointer<Key> key;
	CssmData outData;
	CssmDbRecordAttributeData *outAttrs; mach_msg_type_number_t outAttrsLength;
	record->database().findRecordHandle(record, attrs.attribute_data(), attrs.length(),
		getData ? &outData : NULL, key, outAttrs, outAttrsLength);

	// return handles
	*hKey = key ? key->handle() : noKey;

    if (outAttrsLength && outAttrs) {
        Server::releaseWhenDone(outAttrs); // exception proof it against next line
        if (!copyin(outAttrs, reinterpret_cast<xdrproc_t> (xdr_CSSM_DB_RECORD_ATTRIBUTE_DATA), outAttributes, outAttributesLength))
            CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
        Server::releaseWhenDone(*outAttributes);
    }

	// return data (temporary fix)
	if (getData) {
		/*
			We can't release this with the usual allocator (which calls free(), since
			it was VM allocated. Part of the fix for:
			<rdar://problem/6738709> securityd leaks VM memory during certain smartcard operations
			will be to call Server::releaseWhenDone below with a new vm allocator param
		*/
		Server::releaseWhenDone(outData.data());
        xdrproc_t encode_proc = reinterpret_cast<xdrproc_t>(xdr_CSSM_NO_KEY_IN_DATA);
        if (key)
            encode_proc = reinterpret_cast<xdrproc_t>(xdr_CSSM_KEY_IN_DATA);
        if (!copyin(&outData, encode_proc, data, dataLength))
            CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
        Server::releaseWhenDone(*data);
	}
	END_IPC(DL)
}

kern_return_t ucsp_server_insertRecord(UCSP_ARGS, DbHandle db, CSSM_DB_RECORDTYPE recordType,
	DATA_IN(inAttributes), DATA_IN(data), IPCRecordHandle *record)
{
	BEGIN_IPC(insertRecord)
	RecordHandle recordHandle;
	CopyOutDbRecordAttributes attrs(inAttributes, inAttributesLength);
	Server::database(db)->insertRecord(recordType, attrs.attribute_data(), attrs.length(),
		DATA(data), recordHandle);
	*record = recordHandle;
	END_IPC(DL)
}

kern_return_t ucsp_server_modifyRecord(UCSP_ARGS, DbHandle db, IPCRecordHandle *hRecord,
	CSSM_DB_RECORDTYPE recordType, DATA_IN(attributes),
	boolean_t setData, DATA_IN(data), CSSM_DB_MODIFY_MODE modifyMode)
{
	BEGIN_IPC(modifyRecord)
	CopyOutDbRecordAttributes attrs(attributes, attributesLength);
	CssmData newData(DATA(data));
	RefPointer<Database::Record> record =
		Server::find<Database::Record>(*hRecord, CSSMERR_DL_INVALID_RECORD_UID);
	Server::database(db)->modifyRecord(recordType, record, attrs.attribute_data(), attrs.length(),
		setData ? &newData : NULL, modifyMode);
	// note that the record handle presented to the client never changes here
	// (we could, but have no reason to - our record handles are just always up to date)
	END_IPC(DL)
}

kern_return_t ucsp_server_deleteRecord(UCSP_ARGS, DbHandle db, IPCRecordHandle hRecord)
{
	BEGIN_IPC(deleteRecord)
	Server::database(db)->deleteRecord(
		Server::find<Database::Record>(hRecord, CSSMERR_DL_INVALID_RECORD_UID));
	END_IPC(DL)
}

kern_return_t ucsp_server_releaseSearch(UCSP_ARGS, SearchHandle hSearch)
{
	BEGIN_IPC(releaseSearch)
	RefPointer<Database::Search> search = Server::find<Database::Search>(hSearch, 0);
	search->database().releaseSearch(*search);
	END_IPC(DL)
}

kern_return_t ucsp_server_releaseRecord(UCSP_ARGS, IPCRecordHandle hRecord)
{
	BEGIN_IPC(releaseRecord)
	RefPointer<Database::Record> record = Server::find<Database::Record>(hRecord, 0);
	record->database().releaseRecord(*record);
	END_IPC(DL)
}


//
// Internal database management
//
kern_return_t ucsp_server_createDb(UCSP_ARGS, DbHandle *db,
	DATA_IN(ident), DATA_IN(cred), DATA_IN(owner),
    DBParameters params)
{
	BEGIN_IPC(createDb)
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutEntryAcl owneracl(owner, ownerLength);
	CopyOut flatident(ident, identLength, reinterpret_cast<xdrproc_t>(xdr_DLDbFlatIdentifierRef));
    checkPathLength((*reinterpret_cast<DLDbFlatIdentifier*>(flatident.data())).name);
#ifndef __clang_analyzer__
	*db = (new KeychainDatabase(*reinterpret_cast<DLDbFlatIdentifier*>(flatident.data()), params, connection.process(), creds, owneracl))->handle();
#endif
	END_IPC(DL)
}

kern_return_t ucsp_server_cloneDb(UCSP_ARGS, DbHandle srcDb, DATA_IN(ident), DbHandle *newDb) {
    BEGIN_IPC(cloneDb)

    secnotice("integrity", "cloning a db");

    CopyOut flatident(ident, identLength, reinterpret_cast<xdrproc_t>(xdr_DLDbFlatIdentifierRef));

    checkPathLength((*reinterpret_cast<DLDbFlatIdentifier*>(flatident.data())).name);

    RefPointer<KeychainDatabase> srcKC = Server::keychain(srcDb);
    secnotice("integrity", "cloning db %d", srcKC->handle());

#ifndef __clang_analyzer__
    KeychainDatabase* newKC = new KeychainDatabase(*reinterpret_cast<DLDbFlatIdentifier*>(flatident.data()), *srcKC, connection.process());
    secnotice("integrity", "returning db %d", newKC->handle());
    *newDb = newKC->handle();
#endif

    END_IPC(DL)
}

kern_return_t ucsp_server_recodeDbForSync(UCSP_ARGS, DbHandle dbToClone,
	DbHandle srcDb, DbHandle *newDb)
{
	BEGIN_IPC(recodeDbForSync)
	RefPointer<KeychainDatabase> srcKC = Server::keychain(srcDb);
#ifndef __clang_analyzer__
	*newDb = (new KeychainDatabase(*srcKC, connection.process(), dbToClone))->handle();
#endif
	END_IPC(DL)
}

kern_return_t ucsp_server_recodeDbToVersion(UCSP_ARGS, uint32 newVersion, DbHandle srcDb, DbHandle *newDb)
{
    BEGIN_IPC(recodeDbToVersion)
    RefPointer<KeychainDatabase> srcKC = Server::keychain(srcDb);

    // You can only recode an unlocked keychain, so let's make sure.
    srcKC->unlockDb(false);

    KeychainDatabase* newKC = new KeychainDatabase(newVersion, *srcKC, connection.process());
    if(newKC->blob()->version() != newVersion) {
        CssmError::throwMe(CSSM_ERRCODE_INCOMPATIBLE_VERSION);
    }

    *newDb = newKC->handle();

    END_IPC(DL)
}

kern_return_t ucsp_server_recodeFinished(UCSP_ARGS, DbHandle db)
{
    BEGIN_IPC(recodeDbToVersion)
    Server::keychain(db)->recodeFinished();
    END_IPC(DL)
}


kern_return_t ucsp_server_authenticateDbsForSync(UCSP_ARGS, DATA_IN(dbHandleArray),
	DATA_IN(agentData), DbHandle* authenticatedDBHandle)
{
	BEGIN_IPC(authenticateDbsForSync)
	QueryDBBlobSecret query;
	query.inferHints(connection.process());
    query.addHint(AGENT_HINT_KCSYNC_DICT, agentData, agentDataLength);
	CSSM_DATA dbData = DATA(dbHandleArray);
	uint8 ipcDbHandleArrayCount = *(dbData.Data);
	DbHandle *ipcDbHandleArray = (DbHandle *)Allocator::standard().malloc(ipcDbHandleArrayCount * sizeof(DbHandle));
	if ( ipcDbHandleArray == 0 )
        CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	DbHandle *currIPCDbHandleArrayPtr = ipcDbHandleArray;
	DbHandle *dbHandleArrayPtr = (DbHandle *)(dbData.Data+1);
	int index;
	for (index=0; index < ipcDbHandleArrayCount; index++)
	{
		*currIPCDbHandleArrayPtr = *dbHandleArrayPtr;
		Server::keychain(*currIPCDbHandleArrayPtr)->lockDb(); // lock this db if it was unlocked in the past (user could have deleted the kc, resetLogin, etc.)
		currIPCDbHandleArrayPtr++;
		dbHandleArrayPtr++;
	}
	Server::releaseWhenDone(ipcDbHandleArray);
	if (query(ipcDbHandleArray, ipcDbHandleArrayCount, authenticatedDBHandle) != SecurityAgent::noReason)
        CssmError::throwMe(CSSM_ERRCODE_OPERATION_AUTH_DENIED);
	END_IPC(DL)
}

kern_return_t ucsp_server_commitDbForSync(UCSP_ARGS, DbHandle srcDb,
    DbHandle cloneDb, DATA_OUT(blob))
{
	BEGIN_IPC(commitDbForSync)
    RefPointer<KeychainDatabase> srcKC = Server::keychain(srcDb);
    RefPointer<KeychainDatabase> cloneKC = Server::keychain(cloneDb);
    srcKC->commitSecretsForSync(*cloneKC);

	// re-encode blob for convenience
	if (blob && blobLength) {
		DbBlob *dbBlob = srcKC->blob();
		*blob = dbBlob;
		*blobLength = dbBlob->length();
	} else {
		secinfo("kcrecode", "No blob can be returned to client");
	}
	END_IPC(DL)
}

kern_return_t ucsp_server_decodeDb(UCSP_ARGS, DbHandle *db,
    DATA_IN(ident), DATA_IN(cred), DATA_IN(blob))
{
	BEGIN_IPC(decodeDb)
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOut flatident(ident, identLength, reinterpret_cast<xdrproc_t>(xdr_DLDbFlatIdentifierRef));
	DLDbFlatIdentifier* flatID = (DLDbFlatIdentifier*) flatident.data();
	DLDbIdentifier id = *flatID; // invokes a casting operator

    checkPathLength(id.dbName());

#ifndef __clang_analyzer__
	*db = (new KeychainDatabase(id, SSBLOB(DbBlob, blob),
        connection.process(), creds))->handle();
#endif
	END_IPC(DL)
}

kern_return_t ucsp_server_encodeDb(UCSP_ARGS, DbHandle db, DATA_OUT(blob))
{
	BEGIN_IPC(encodeDb)
    DbBlob *dbBlob = Server::keychain(db)->blob();	// memory owned by database
    *blob = dbBlob;
    *blobLength = dbBlob->length();
	END_IPC(DL)
}

kern_return_t ucsp_server_setDbParameters(UCSP_ARGS, DbHandle db, DBParameters params)
{
	BEGIN_IPC(setDbParameters)
	Server::keychain(db)->setParameters(params);
	END_IPC(DL)
}

kern_return_t ucsp_server_getDbParameters(UCSP_ARGS, DbHandle db, DBParameters *params)
{
	BEGIN_IPC(getDbParameters)
	Server::keychain(db)->getParameters(*params);
	END_IPC(DL)
}

kern_return_t ucsp_server_changePassphrase(UCSP_ARGS, DbHandle db,
    DATA_IN(cred))
{
	BEGIN_IPC(changePassphrase)
	CopyOutAccessCredentials creds(cred, credLength);
	Server::keychain(db)->changePassphrase(creds);
	END_IPC(DL)
}

kern_return_t ucsp_server_lockAll (UCSP_ARGS, boolean_t)
{
	BEGIN_IPC(lockAll)
	connection.session().processLockAll();
	END_IPC(DL)
}

kern_return_t ucsp_server_unlockDb(UCSP_ARGS, DbHandle db)
{
	BEGIN_IPC(unlockDb)
	Server::keychain(db)->unlockDb(true);
	END_IPC(DL)
}

static void check_stash_entitlement(Process & proc)
{
    OSStatus status = noErr;
    CFDictionaryRef code_info = NULL;
    CFDictionaryRef entitlements = NULL;
    CFTypeRef value = NULL;
    bool entitled = false;

    status = proc.copySigningInfo(kSecCSRequirementInformation, &code_info);
    __Require_noErr(status, done);

    if (CFDictionaryGetValueIfPresent(code_info, kSecCodeInfoEntitlementsDict, &value)) {
        if (CFGetTypeID(value) == CFDictionaryGetTypeID()) {
            entitlements = (CFDictionaryRef)value;
        }
    }
    __Require(entitlements != NULL, done);

    if (CFDictionaryGetValueIfPresent(entitlements, kSecEntitlementPrivateStash, &value)) {
        if (CFGetTypeID(value) && CFBooleanGetTypeID()) {
            entitled = CFBooleanGetValue((CFBooleanRef)value);
        }
    }

done:
    if (code_info) {
        CFRelease(code_info);
    }

    if (!entitled) {
        CssmError::throwMe(CSSM_ERRCODE_OS_ACCESS_DENIED);
    }
}

kern_return_t ucsp_server_unlockDbWithPassphrase(UCSP_ARGS, DbHandle db, DATA_IN(passphrase))
{
	BEGIN_IPC(unlockDbWithPassphrase)
    Server::keychain(db)->unlockDb(DATA(passphrase), true);
	END_IPC(DL)
}

kern_return_t ucsp_server_stashDb(UCSP_ARGS, DbHandle db)
{
    BEGIN_IPC(stashDb)
    check_stash_entitlement(connection.process());
    Server::keychain(db)->stashDb();
    END_IPC(DL)
}

kern_return_t ucsp_server_stashDbCheck(UCSP_ARGS, DbHandle db)
{
    BEGIN_IPC(stashDbCheck)
    check_stash_entitlement(connection.process());
    Server::keychain(db)->stashDbCheck();
    END_IPC(DL)
}

kern_return_t ucsp_server_isLocked(UCSP_ARGS, DbHandle db, boolean_t *locked)
{
    BEGIN_IPC(isLocked)
    // Must hold the DB's common's lock to safely determine if it's locked. Locking is a mess in there.
    StLock<Mutex> _(Server::database(db)->common());
    *locked = Server::database(db)->isLocked();
    END_IPC(DL)
}

kern_return_t ucsp_server_verifyKeyStorePassphrase(UCSP_ARGS, uint32_t retries)
{
    BEGIN_IPC(verifyKeyStorePassphrase)
    connection.process().session().verifyKeyStorePassphrase(retries);
    END_IPC(DL)
}

kern_return_t ucsp_server_changeKeyStorePassphrase(UCSP_ARGS)
{
    BEGIN_IPC(verifyKeyStorePassphrase)
    connection.process().session().changeKeyStorePassphrase();
    END_IPC(DL)
}

kern_return_t ucsp_server_resetKeyStorePassphrase(UCSP_ARGS, DATA_IN(passphrase))
{
    BEGIN_IPC(verifyKeyStorePassphrase)
    connection.process().session().resetKeyStorePassphrase(DATA(passphrase));
    END_IPC(DL)
}

//
// Key management
//
kern_return_t ucsp_server_encodeKey(UCSP_ARGS, KeyHandle keyh, DATA_OUT(blob),
    boolean_t wantUid, DATA_OUT(uid))
{
	BEGIN_IPC(encodeKey)
	RefPointer<Key> gKey = Server::key(keyh);
	if (KeychainKey *key = dynamic_cast<KeychainKey *>(gKey.get())) {
		KeyBlob *keyBlob = key->blob();	// still owned by key
		*blob = keyBlob;
		*blobLength = keyBlob->length();
		if (wantUid) {	// uid generation is not implemented
			CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
		} else {
			*uidLength = 0;	// do not return this
		}
	} else {	// not a KeychainKey
		CssmError::throwMe(CSSMERR_CSP_INVALID_KEY_REFERENCE);
	}
	END_IPC(CSP)
}

kern_return_t ucsp_server_decodeKey(UCSP_ARGS, KeyHandle *keyh, DATA_OUT(keyHeader),
	DbHandle db, DATA_IN(blob))
{
	BEGIN_IPC(decodeKey)
    RefPointer<Key> key = new KeychainKey(*Server::keychain(db), SSBLOB(KeyBlob, blob));
	CssmKey::Header header;
    key->returnKey(*keyh, header);
	if (!copyin(&header, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), keyHeader, keyHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*keyHeader);
	END_IPC(CSP)
}

// keychain synchronization
kern_return_t ucsp_server_recodeKey(UCSP_ARGS, DbHandle oldDb, KeyHandle keyh,
	DbHandle newDb, DATA_OUT(newBlob))
{
	BEGIN_IPC(recodeKey)
	// If the old key is passed in as DATA_IN(oldBlob):
	// RefPointer<KeychainKey> key = new KeychainKey(*Server::keychain(oldDb), SSBLOB(KeyBlob, oldBlob));
	RefPointer<Key> key = Server::key(keyh);
	if (KeychainKey *kckey = dynamic_cast<KeychainKey *>(key.get())) {
		KeyBlob *blob = Server::keychain(newDb)->recodeKey(*kckey);
		*newBlob = blob;
		*newBlobLength = blob->length();
		Server::releaseWhenDone(*newBlob);
		// @@@  stop leaking blob
	} else {	// not a KeychainKey
		CssmError::throwMe(CSSMERR_CSP_INVALID_KEY_REFERENCE);
	}
	END_IPC(CSP)
}

kern_return_t ucsp_server_releaseKey(UCSP_ARGS, KeyHandle keyh)
{
	BEGIN_IPC(releaseKey)
	RefPointer<Key> key = Server::key(keyh);
	key->database().releaseKey(*key);
	END_IPC(CSP)
}

kern_return_t ucsp_server_queryKeySizeInBits(UCSP_ARGS, KeyHandle keyh, CSSM_KEY_SIZE *length)
{
	BEGIN_IPC(queryKeySizeInBits)
	RefPointer<Key> key = Server::key(keyh);
	key->database().queryKeySizeInBits(*key, CssmKeySize::overlay(*length));
	END_IPC(CSP)
}

kern_return_t ucsp_server_getOutputSize(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
    uint32 inputSize, boolean_t encrypt, uint32 *outputSize)
{
    BEGIN_IPC(getOutputSize)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
    key->database().getOutputSize(*ctx, *key, inputSize, encrypt, *outputSize);
    END_IPC(CSP)
}

kern_return_t ucsp_server_getKeyDigest(UCSP_ARGS, KeyHandle key, DATA_OUT(digest))
{
	BEGIN_IPC(getKeyDigest)
	CssmData digestData = Server::key(key)->canonicalDigest();
	*digest = digestData.data();
	*digestLength = int_cast<size_t, mach_msg_type_number_t>(digestData.length());
	END_IPC(CSP)
}

kern_return_t ucsp_server_getPublicKey(UCSP_ARGS, DATA_IN(context), KeyHandle key, DATA_OUT(pubKey))
{
    BEGIN_IPC(getKeyDigest)
    CopyOutContext ctx(context, contextLength);
    OutputData pubKeyData(pubKey, pubKeyLength);
    Server::key(key)->publicKey(*ctx, pubKeyData);
    END_IPC(CSP)
}


//
// Signatures and MACs
//
kern_return_t ucsp_server_generateSignature(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
        CSSM_ALGORITHMS signOnlyAlgorithm, DATA_IN(data), DATA_OUT(signature))
{
	BEGIN_IPC(generateSignature)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
	OutputData sigData(signature, signatureLength);
	key->database().generateSignature(*ctx, *key, signOnlyAlgorithm,
		DATA(data), sigData);
	END_IPC(CSP)
}

kern_return_t ucsp_server_verifySignature(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
		CSSM_ALGORITHMS verifyOnlyAlgorithm, DATA_IN(data), DATA_IN(signature))
{
	BEGIN_IPC(verifySignature)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
	key->database().verifySignature(*ctx, *key, verifyOnlyAlgorithm,
		DATA(data), DATA(signature));
	END_IPC(CSP)
}

kern_return_t ucsp_server_generateMac(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
		DATA_IN(data), DATA_OUT(mac))
{
	BEGIN_IPC(generateMac)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
	OutputData macData(mac, macLength);
	key->database().generateMac(*ctx, *key, DATA(data), macData);
	END_IPC(CSP)
}

kern_return_t ucsp_server_verifyMac(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
		DATA_IN(data), DATA_IN(mac))
{
	BEGIN_IPC(verifyMac)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
	key->database().verifyMac(*ctx, *key, DATA(data), DATA(mac));
	END_IPC(CSP)
}


//
// Encryption/Decryption
//
kern_return_t ucsp_server_encrypt(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
	DATA_IN(clear), DATA_OUT(cipher))
{
	BEGIN_IPC(encrypt)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
	OutputData cipherOut(cipher, cipherLength);
	key->database().encrypt(*ctx, *key, DATA(clear), cipherOut);
	END_IPC(CSP)
}

kern_return_t ucsp_server_decrypt(UCSP_ARGS, DATA_IN(context), KeyHandle keyh,
	DATA_IN(cipher), DATA_OUT(clear))
{
	BEGIN_IPC(decrypt)
	CopyOutContext ctx(context, contextLength);
	RefPointer<Key> key = Server::key(keyh);
	OutputData clearOut(clear, clearLength);
	key->database().decrypt(*ctx, *key, DATA(cipher), clearOut);
	END_IPC(CSP)
}


//
// Key generation
//
kern_return_t ucsp_server_generateKey(UCSP_ARGS, DbHandle db, DATA_IN(context),
	DATA_IN(cred), DATA_IN(owner),
	uint32 usage, uint32 attrs, KeyHandle *newKey, DATA_OUT(keyHeader))
{
	BEGIN_IPC(generateKey)
	CopyOutContext ctx(context, contextLength);
	CopyOutAccessCredentials creds(cred, credLength);

	CopyOutEntryAcl owneracl(owner, ownerLength);
	//@@@ preliminary interpretation - will get "type handle"
	RefPointer<Database> database =
		Server::optionalDatabase(db, attrs & CSSM_KEYATTR_PERMANENT);
	RefPointer<Key> key;
	database->generateKey(*ctx, creds, owneracl, usage, attrs, key);
	CssmKey::Header newHeader;
    key->returnKey(*newKey, newHeader);

	if (!copyin(&newHeader, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), keyHeader, keyHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*keyHeader);
	END_IPC(CSP)
}

kern_return_t ucsp_server_generateKeyPair(UCSP_ARGS, DbHandle db, DATA_IN(context),
	DATA_IN(cred), DATA_IN(owner),
	uint32 pubUsage, uint32 pubAttrs, uint32 privUsage, uint32 privAttrs,
	KeyHandle *pubKey, DATA_OUT(pubHeader), KeyHandle *privKey, DATA_OUT(privHeader))
{
	BEGIN_IPC(generateKeyPair)
	CopyOutContext ctx(context, contextLength);
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutEntryAcl owneracl(owner, ownerLength);
	RefPointer<Database> database =
		Server::optionalDatabase(db, (privAttrs | pubAttrs) & CSSM_KEYATTR_PERMANENT);
	RefPointer<Key> pub, priv;
	database->generateKey(*ctx, creds, owneracl,
		pubUsage, pubAttrs, privUsage, privAttrs, pub, priv);
	CssmKey::Header tmpPubHeader, tmpPrivHeader;

    pub->returnKey(*pubKey, tmpPubHeader);
	if (!copyin(&tmpPubHeader, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), pubHeader, pubHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*pubHeader);

    priv->returnKey(*privKey, tmpPrivHeader);
	if (!copyin(&tmpPrivHeader, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), privHeader, privHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*privHeader);

	END_IPC(CSP)
}


//
// Key wrapping and unwrapping
//
kern_return_t ucsp_server_wrapKey(UCSP_ARGS, DATA_IN(context), KeyHandle hWrappingKey,
	DATA_IN(cred), KeyHandle hKeyToBeWrapped,
	DATA_IN(descriptiveData), DATA_OUT(wrappedKeyData))
{
	BEGIN_IPC(wrapKey)
	CssmKey wrappedKey;
	CopyOutContext ctx(context, contextLength);
	CopyOutAccessCredentials creds(cred, credLength);
	RefPointer<Key> subjectKey = Server::key(hKeyToBeWrapped);
	RefPointer<Key> wrappingKey = Server::optionalKey(hWrappingKey);
	if ((ctx.context().algorithm() == CSSM_ALGID_NONE && subjectKey->attribute(CSSM_KEYATTR_SENSITIVE))
		|| !subjectKey->attribute(CSSM_KEYATTR_EXTRACTABLE))
		CssmError::throwMe(CSSMERR_CSP_INVALID_KEYATTR_MASK);
	pickDb(subjectKey, wrappingKey)->wrapKey(*ctx, creds, wrappingKey, *subjectKey, DATA(descriptiveData), wrappedKey);
	Server::releaseWhenDone(wrappedKey.keyData().data());

	if (!copyin(&wrappedKey, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEY), wrappedKeyData, wrappedKeyDataLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);

	Server::releaseWhenDone(*wrappedKeyData);
	END_IPC(CSP)
}

kern_return_t ucsp_server_unwrapKey(UCSP_ARGS, DbHandle db, DATA_IN(context),
	KeyHandle hWrappingKey, DATA_IN(cred), DATA_IN(owner),
	KeyHandle hPublicKey, DATA_IN(wrappedKeyData),
	CSSM_KEYUSE usage, CSSM_KEYATTR_FLAGS attrs, DATA_OUT(descriptiveData),
    KeyHandle *newKey, DATA_OUT(keyHeader)/*CssmKey::Header *newHeader*/)
{
	BEGIN_IPC(unwrapKey)
	CopyOutContext ctx(context, contextLength);
	CopyOutKey wrappedKey(wrappedKeyData, wrappedKeyDataLength);
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutEntryAcl owneracl(owner, ownerLength);
	OutputData descriptiveDatas(descriptiveData, descriptiveDataLength);
	RefPointer<Key> wrappingKey = Server::optionalKey(hWrappingKey);
    RefPointer<Key> unwrappedKey;
	pickDb(Server::optionalDatabase(db), wrappingKey)->unwrapKey(*ctx, creds, owneracl,
		wrappingKey, Server::optionalKey(hPublicKey),
		usage, attrs, wrappedKey.key(), unwrappedKey, descriptiveDatas);

	CssmKey::Header newHeader;
	unwrappedKey->returnKey(*newKey, newHeader);
	if (!copyin(&newHeader, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), keyHeader, keyHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*keyHeader);

	END_IPC(CSP)
}


//
// Key derivation.
//
// Note that the "param" argument can have structure. The walker for the
// (artificial) POD CssmDeriveData handles those that are known; if you add
// an algorithm with structured param, you need to add a case there.
//
kern_return_t ucsp_server_deriveKey(UCSP_ARGS, DbHandle db, DATA_IN(context), KeyHandle hKey,
	DATA_IN(cred), DATA_IN(owner),
    DATA_IN(paramInput), DATA_OUT(paramOutput),
	uint32 usage, uint32 attrs, KeyHandle *newKey, DATA_OUT(keyHeader))
{
	BEGIN_IPC(deriveKey)
	CopyOutContext ctx(context, contextLength);
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutEntryAcl owneracl(owner, ownerLength);
	CopyOutDeriveData deriveParam(paramInput, paramInputLength);
	if (deriveParam.algorithm() != ctx.context().algorithm())
		CssmError::throwMe(CSSMERR_CSP_INTERNAL_ERROR);	// client layer fault

	RefPointer<Database> database =
		Server::optionalDatabase(db, attrs & CSSM_KEYATTR_PERMANENT);
	RefPointer<Key> key = Server::optionalKey(hKey);
	CSSM_DATA param = deriveParam.cssm_data();
	RefPointer<Key> derivedKey;
	pickDb(Server::optionalDatabase(db, attrs & CSSM_KEYATTR_PERMANENT),
		key)->deriveKey(*ctx, key, creds, owneracl, static_cast<CssmData*>(&param), usage, attrs, derivedKey);

	CssmKey::Header newHeader;
	derivedKey->returnKey(*newKey, newHeader);

	if (!copyin(&newHeader, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), keyHeader, keyHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*keyHeader);

	if (param.Length) {
        if (!param.Data)	// CSP screwed up
            CssmError::throwMe(CSSM_ERRCODE_INTERNAL_ERROR);
		OutputData(paramOutput, paramOutputLength) = CssmAutoData(Server::csp().allocator(), param).release();
    }
	END_IPC(CSP)
}

//
// ACL management.
// Watch out for the memory-management tap-dance.
//
kern_return_t ucsp_server_getOwner(UCSP_ARGS, AclKind kind, KeyHandle key,
	DATA_OUT(ownerOut))
{
	BEGIN_IPC(getOwner)
	AclOwnerPrototype owner;
	Server::aclBearer(kind, key).getOwner(owner);	// allocates memory in owner
	void *owners_data; u_int owners_length;
	if (!::copyin(&owner, reinterpret_cast<xdrproc_t>(xdr_CSSM_ACL_OWNER_PROTOTYPE), &owners_data, &owners_length))
			CssmError::throwMe(CSSM_ERRCODE_MEMORY_ERROR);

	{ ChunkFreeWalker free; walk(free, owner); } // release chunked original
	Server::releaseWhenDone(owners_data); // throw flat copy out when done
	*ownerOut = owners_data;
	*ownerOutLength = owners_length;
	END_IPC(CSP)
}

kern_return_t ucsp_server_setOwner(UCSP_ARGS, AclKind kind, KeyHandle key,
	DATA_IN(cred), DATA_IN(owner))
{
	BEGIN_IPC(setOwner)
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutOwnerAcl owneracl(owner, ownerLength);
	Server::aclBearer(kind, key).changeOwner(*owneracl, creds);
	END_IPC(CSP)
}

kern_return_t ucsp_server_getAcl(UCSP_ARGS, AclKind kind, KeyHandle key,
	boolean_t haveTag, const char *tag,
	uint32 *countp, DATA_OUT(acls))
{
	BEGIN_IPC(getAcl)
	uint32 count;
	AclEntryInfo *aclList;

    AclSource& aclRef = Server::aclBearer(kind, key);
    secinfo("SecAccess", "getting the ACL for handle %d [%d] (%p)", key, (uint32_t) kind, &aclRef);
    aclRef.getAcl(haveTag ? tag : NULL, count, aclList);

	CSSM_ACL_ENTRY_INFO_ARRAY aclsArray = { count, aclList };
	void *acls_data; u_int acls_length;
	if (!::copyin(&aclsArray, reinterpret_cast<xdrproc_t>(xdr_CSSM_ACL_ENTRY_INFO_ARRAY), &acls_data, &acls_length))
			CssmError::throwMe(CSSM_ERRCODE_MEMORY_ERROR);

	{       // release the chunked memory originals
			ChunkFreeWalker free;
			for (uint32 n = 0; n < count; n++)
					walk(free, aclList[n]);

			// release the memory allocated for the list itself when we are done
			Allocator::standard().free (aclList);
	}


	*countp = count; // XXX/cs count becomes part of the blob
	*aclsLength = acls_length;
	*acls = acls_data;
	Server::releaseWhenDone(acls_data);
	END_IPC(CSP)
}

kern_return_t ucsp_server_changeAcl(UCSP_ARGS, AclKind kind, KeyHandle key,
	DATA_IN(cred), CSSM_ACL_EDIT_MODE mode, GenericHandle handle,
	DATA_IN(acl))
{
	BEGIN_IPC(changeAcl)
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutAclEntryInput entryacl(acl, aclLength);

    AclSource& aclRef = Server::aclBearer(kind, key);
    secinfo("SecAccess", "changing the ACL for handle %d [%d] (%p)", key, (uint32_t) kind, &aclRef);
    aclRef.changeAcl(AclEdit(mode, handle, entryacl), creds);

	END_IPC(CSP)
}


//
// Login/Logout
//
kern_return_t ucsp_server_login(UCSP_ARGS, DATA_IN(cred), DATA_IN(name))
{
	BEGIN_IPC(login)
	CopyOutAccessCredentials creds(cred, credLength);
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}

kern_return_t ucsp_server_logout(UCSP_ARGS)
{
	BEGIN_IPC(logout)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}


//
// Miscellaneous CSP-related calls
//
kern_return_t ucsp_server_getStatistics(UCSP_ARGS, uint32 ssid, CSSM_CSP_OPERATIONAL_STATISTICS *statistics)
{
	BEGIN_IPC(getStatistics)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}

kern_return_t ucsp_server_getTime(UCSP_ARGS, uint32 ssid, CSSM_ALGORITHMS algorithm, DATA_OUT(data))
{
	BEGIN_IPC(getTime)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}

kern_return_t ucsp_server_getCounter(UCSP_ARGS, uint32 ssid, DATA_OUT(data))
{
	BEGIN_IPC(getCounter)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}

kern_return_t ucsp_server_selfVerify(UCSP_ARGS, uint32 ssid)
{
	BEGIN_IPC(selfVerify)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}


//
// Passthrough calls (separate for CSP and DL passthroughs)
//
kern_return_t ucsp_server_cspPassThrough(UCSP_ARGS, uint32 ssid, uint32 id, DATA_IN(context),
	KeyHandle hKey, DATA_IN(inData), DATA_OUT(outData))
{
	BEGIN_IPC(cspPassThrough)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(CSP)
}

kern_return_t ucsp_server_dlPassThrough(UCSP_ARGS, uint32 ssid, uint32 id,
	DATA_IN(inData), DATA_OUT(outData))
{
	BEGIN_IPC(dlPassThrough)
	CssmError::throwMe(CSSM_ERRCODE_FUNCTION_NOT_IMPLEMENTED);
	END_IPC(DL)
}


//
// Database key management.
// ExtractMasterKey looks vaguely like a key derivation operation, and is in fact
// presented by the CSPDL's CSSM layer as such.
//
kern_return_t ucsp_server_extractMasterKey(UCSP_ARGS, DbHandle db, DATA_IN(context), DbHandle sourceDb,
	DATA_IN(cred), DATA_IN(owner),
	uint32 usage, uint32 attrs, KeyHandle *newKey, DATA_OUT(keyHeader))
{
	BEGIN_IPC(extractMasterKey)
	CopyOutAccessCredentials creds(cred, credLength);
	CopyOutEntryAcl owneracl(owner, ownerLength);
	CopyOutContext ctx(context, contextLength);
	RefPointer<KeychainDatabase> keychain = Server::keychain(sourceDb);
	RefPointer<Key> masterKey = keychain->extractMasterKey(
		*Server::optionalDatabase(db, attrs & CSSM_KEYATTR_PERMANENT),
		creds, owneracl, usage, attrs);
	CssmKey::Header header;
	masterKey->returnKey(*newKey, header);
	if (!copyin(&header, reinterpret_cast<xdrproc_t> (xdr_CSSM_KEYHEADER), keyHeader, keyHeaderLength))
		CssmError::throwMe(CSSMERR_CSSM_MEMORY_ERROR);
	Server::releaseWhenDone(*keyHeader);
	END_IPC(CSP)
}


//
// Notification core subsystem
//

kern_return_t ucsp_server_postNotification(UCSP_ARGS, uint32 domain, uint32 event,
	DATA_IN(data), uint32 sequence)
{
	BEGIN_IPC(postNotification)
		Listener::notify(domain, event, sequence, DATA(data), auditToken);
	END_IPC(CSSM)
}


//
// Child check-in service.
// Note that this isn't using the standard argument pattern.
//
kern_return_t ucsp_server_childCheckIn(audit_token_t auditToken, mach_port_t serverPort,
	mach_port_t servicePort, mach_port_t taskPort)
{
	BEGIN_IPCS
	ServerChild::checkIn(servicePort, audit_token_to_pid(auditToken));
    // Will be NULL from newer frameworks, but mach_port_deallocate doesn't seem to mind
	END_IPCS(mach_port_deallocate(mach_task_self(), taskPort))
}


//
// Testing-related RPCs
//
kern_return_t ucsp_server_getUserPromptAttempts(UCSP_ARGS, uint32* attempts)
{
    BEGIN_IPC(keychainPromptAttempts)

    *attempts = KeychainPromptAclSubject::getPromptAttempts() + KeychainDatabase::getInteractiveUnlockAttempts();

    END_IPC(DL)
}

kern_return_t ucsp_server_setup(UCSP_ARGS, mach_port_t taskToken, ClientSetupInfo info, const char *identity)
{
    return KERN_FAILURE;
}


kern_return_t ucsp_server_setupThread(UCSP_ARGS, mach_port_t taskToken)
{
    return KERN_FAILURE;
}

#pragma clang diagnostic pop
