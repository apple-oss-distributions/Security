/*
 * Copyright (c) 2000-2008,2012-2013 Apple Inc. All Rights Reserved.
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
// kcdatabase - software database container implementation.
//
// A KeychainDatabase is a software storage container,
// implemented in cooperation by the AppleCSLDP CDSA plugin and this daemon.
//
#ifndef _H_KCDATABASE
#define _H_KCDATABASE

#include "localdatabase.h"
#include <securityd_client/ss_types.h>
#include "agentclient.h"

class KeychainDatabase;
class KeychainDbCommon;
class KeychainKey;


//
// We identify KeychainDatabases uniquely by a combination of
// a DLDbIdentifier and a database (blob) identifier. Equivalence
// by DbIdentifier is the criterion for parent-side merging.
//
class DbIdentifier {
public:
	DbIdentifier(const DLDbIdentifier &id, DbBlob::Signature sig)
	: mIdent(id), mSig(sig) { }
	
	const DLDbIdentifier &dlDbIdentifier() const { return mIdent; }
	const DbBlob::Signature &signature() const { return mSig; }
	operator const DLDbIdentifier &() const { return dlDbIdentifier(); }
	operator const DbBlob::Signature &() const	{ return signature(); }
	const char *dbName() const			{ return mIdent.dbName(); }
	
	bool operator < (const DbIdentifier &id) const	// simple lexicographic
	{
		if (mIdent < id.mIdent) return true;
		if (id.mIdent < mIdent) return false;
		return mSig < id.mSig;
	}
	
	bool operator == (const DbIdentifier &id) const
	{ return mIdent == id.mIdent && mSig == id.mSig; }
	
private:
	DLDbIdentifier mIdent;
	DbBlob::Signature mSig;
};


//
// A vestigal system-global database instance
// We don't (yet) use it for anything. Perhaps it should carry our ACL...
//
class KeychainDbGlobal : public PerGlobal {
public:
	KeychainDbGlobal(const DbIdentifier &id);
	~KeychainDbGlobal();

	const DbIdentifier &identifier() const { return mIdentifier; }

private:
	DbIdentifier mIdentifier;	// database external identifier [const]
};


//
// KeychainDatabase DbCommons
//
class KeychainDbCommon : public LocalDbCommon, 
	public DatabaseCryptoCore, public MachServer::Timer {
public:
    KeychainDbCommon(Session &ssn, const DbIdentifier &id, uint32 requestedVersion = CommonBlob::version_none);
    KeychainDbCommon(Session &ssn, const DbIdentifier &id, KeychainDbCommon& toClone);
	~KeychainDbCommon();

    // If you have an existing KeychainDbCommon, and want to make it look a lot like that one
    void cloneFrom(KeychainDbCommon& toClone, uint32 requestedVersion = CommonBlob::version_none);

    // finishes the initialization of this KeychainDbCommon. Do not call this
    // while holding the mCommon lock, or you may get a multiprocess deadlock.
    void initializeKeybag();

	void kill();                // remove from commonSet
	
	KeychainDbGlobal &global() const;
	
	bool unlockDb(DbBlob *blob, void **privateAclBlob = NULL);
	void lockDb();				// make locked (if currently unlocked)
	bool isLocked()			{ return mIsLocked; } // lock status
	void setUnlocked();
	void invalidateBlob()	{ version++; }
	
	void activity();			// reset lock timeout
	
	void makeNewSecrets();

	const DbIdentifier &identifier() const {return mIdentifier; }
	const DLDbIdentifier &dlDbIdent() const { return identifier(); }
	const char *dbName() const { return dlDbIdent().dbName(); }
    uint32 dbVersion() { return DatabaseCryptoCore::mBlobVersion; }
    bool isLoginKeychain() const { return mLoginKeychain; }
	
	DbBlob *encode(KeychainDatabase &db);
	
	void notify(NotificationEvent event) { DbCommon::notify(event, identifier()); }

	void sleepProcessing();
	void lockProcessing();
	
	bool belongsToSystem() const;
    bool isDefaultSystemKeychain() const;

public:
    // debugging
    IFDUMP(void dumpNode());
	
protected:
	void action();				// timer queue action to lock keychain
	
	// lifetime management for our Timer personality
	void select();
	void unselect();

public:
	// all following data locked with object lock
	uint32 sequence;			// change sequence number
	DBParameters mParams;		// database parameters (arbitrated copy)
	
	uint32 version;				// version stamp for change tracking
	
private:
	DbIdentifier mIdentifier;	// database external identifier [const]
	// all following data protected by object lock
	bool mIsLocked;				// logically locked
	bool mValidParams;			// mParams has been set
    bool mLoginKeychain;

public:
    void insert();              // insert into commonSet
    static bool find(const DbIdentifier &ident, Session &session, RefPointer<KeychainDbCommon> &common,
            uint32 requestedVersion = CommonBlob::version_none, KeychainDbCommon* cloneFrom = NULL); // find in commonSet

private:
    void insertHoldingLock();              // Does the guts of insert(); you must hold a write lock on mRWCommonLock when calling this

    // global set of KeychainDbCommons for name unification
    typedef std::set<KeychainDbCommon *> CommonSet;
    static CommonSet mCommonSet;
    static ReadWriteLock mRWCommonLock;           //protects only mCommonSet
};


//
// A Database object represents an Apple CSP/DL open database (DL/DB) object.
// It maintains its protected semantic state (including keys) and provides controlled
// access.
//
class KeychainDatabase : public LocalDatabase, private virtual SecurityServerAcl {
	friend class KeychainDbCommon;
public:
	KeychainDatabase(const DLDbIdentifier &id, const DBParameters &params, Process &proc,
        const AccessCredentials *cred, const AclEntryPrototype *owner);
	KeychainDatabase(const DLDbIdentifier &id, const DbBlob *blob, Process &proc,
        const AccessCredentials *cred);
	
	// keychain synchronization recode to a specfic blob:
	KeychainDatabase(KeychainDatabase &src, Process &proc, DbHandle dbToClone);

    // Clone another database, but to a new DLDb identifier
    KeychainDatabase(const DLDbIdentifier &id, KeychainDatabase &src, Process &proc);

    // Copy another database, but with new secrets.
    // To use this, you must provide the version you want to end up with.
    KeychainDatabase(uint32 requestedVersion, KeychainDatabase &src, Process &proc);
	virtual ~KeychainDatabase();

	KeychainDbCommon &common() const;
	const char *dbName() const;
	bool transient() const;
    
    KeychainDbGlobal &global() const { return common().global(); }
	
public:	
	static const int maxUnlockTryCount = 3;

public:
    const DbIdentifier &identifier() const { return common().identifier(); }
	
public:
	// encoding/decoding databases
	DbBlob *blob();
	
    void authenticate(CSSM_DB_ACCESS_TYPE mode, const AccessCredentials *cred);
    bool checkCredentials(const AccessCredentials* creds);
    void changePassphrase(const AccessCredentials *cred);
    void changePassphraseTo(const CssmData &passphrase); // for re-encrypting with indirect passphrase
    void changeKeybagPassphrase(const CssmData &oldPassphrase, const CssmData &newPassphrase); // for indirect passphrase case
	RefPointer<Key> extractMasterKey(Database &db, const AccessCredentials *cred,
		const AclEntryPrototype *owner, uint32 usage, uint32 attrs);
    void commitSecretsForSync(KeychainDatabase &cloneDb);
	
	// lock/unlock processing
	void lockDb();											// unconditional lock
	void unlockDb(bool unlockKeybag);                       // full-feature unlock
	void unlockDb(const CssmData &passphrase, bool unlockKeybag);	// unlock with passphrase
	// unlock only the keybag with passphrase, but no-op if this is not a login keychain,
	// as other keychains don't pertain.
	void unlockKeybag(const CssmData &passphrase);
    
    void stashDbCheck();                                    // check AppleKeyStore for master key
    void stashDb();                                         // stash master key in AppleKeyStore

	bool decode();											// unlock given established master key
	bool decode(const CssmData &passphrase);				// set master key from PP, try unlock

	bool validatePassphrase(const CssmData &passphrase) const; // nonthrowing validation
	bool isLocked()			{ return common().isLocked(); }	// lock status
    void notify(NotificationEvent event) { return common().notify(event); }
    void activity() const	{ common().activity(); }		// reset timeout clock
	
	// encoding/decoding keys
    void decodeKey(KeyBlob *blob, CssmKey &key, void * &pubAcl, void * &privAcl);
	KeyBlob *encodeKey(const CssmKey &key, const CssmData &pubAcl, const CssmData &privAcl);
	KeyBlob *recodeKey(KeychainKey &oldKey);	
    bool validBlob() const	{ return mBlob && version == common().version; }

	// manage database parameters
	void setParameters(const DBParameters &params);
	void getParameters(DBParameters &params);
	
	// where's my (database) ACL?
	SecurityServerAcl &acl();
	
	AclKind aclKind() const;
	Database *relatedDatabase();
    
    // ACL state management hooks
	void instantiateAcl();
	void changedAcl();
    	
	// miscellaneous utilities
	static void validateBlob(const DbBlob *blob);

    bool isRecoding();

    // Notify ourselves that the keychain recode/migration has finished
    void recodeFinished();

    // debugging
    IFDUMP(void dumpNode());

protected:
	RefPointer<Key> makeKey(const CssmKey &newKey, uint32 moreAttributes, const AclEntryPrototype *owner);
	RefPointer<Key> makeKey(Database &db, const CssmKey &newKey, uint32 moreAttributes, const AclEntryPrototype *owner);

	void makeUnlocked(bool unlockKeybag);	// interior version of unlock()
	void makeUnlocked(const AccessCredentials *cred, bool unlockKeybag); // like () with explicit cred
	void makeUnlocked(const CssmData &passphrase, bool unlockKeybag);	 // interior version of unlock(CssmData)
	void makeKeybagUnlocked(const CssmData &passphrase);                 // interior version of unlockKeybag(CssmData)
	
	void establishOldSecrets(const AccessCredentials *creds);
	bool establishNewSecrets(const AccessCredentials *creds, SecurityAgent::Reason reason, bool change);
	
	bool interactiveUnlock();
	
	CssmClient::Key keyFromCreds(const TypedList &sample, unsigned int requiredLength);
	CssmClient::Key keyFromKeybag(const TypedList &sample);
	CssmClient::Key makeRawKey(void *data, size_t length, CSSM_ALGORITHMS algid, CSSM_KEYUSE usage);
	
	void encode();									// (re)generate mBlob if needed

    // Counts the number of total interactive unlocks attempted by securityd
    static uint32_t interactiveUnlockAttempts;

public:
    static uint32_t getInteractiveUnlockAttempts();
	
private:
	// all following data is locked by the common lock
    bool mValidData;				// valid ACL and params (blob decoded)
    CssmAutoData mSecret;
    bool mSaveSecret;
        
    uint32 version;					// version stamp for blob validity
    DbBlob *mBlob;					// database blob (encoded)
    
    AccessCredentials *mCred;		// local access credentials (always valid)
	
	RefPointer<KeychainDatabase> mRecodingSource;	// keychain synchronization ONLY; should not require accessors
    bool mRecoded;                  // true once a recode completes, until recodeFinished is called
};

#endif //_H_KCDATABASE
