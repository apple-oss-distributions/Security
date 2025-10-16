/*
 * Copyright (c) 2000-2001,2011,2014 Apple Inc. All Rights Reserved.
 * 
 * The contents of this file constitute Original Code as defined in and are
 * subject to the Apple Public Source License Version 1.2 (the 'License').
 * You may not use this file except in compliance with the License. Please obtain
 * a copy of the License at http://www.apple.com/publicsource and read it before
 * using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS
 * OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. Please see the License for the
 * specific language governing rights and limitations under the License.
 */


//
// DatabaseSession.h - Framework for DL plugin modules
//
#ifndef _H_DATABASESESSION
#define _H_DATABASESESSION

#include <security_cdsa_plugin/DLabstractsession.h>

#include <security_utilities/alloc.h>
#include <security_utilities/threading.h>
#include <Security/cssmtype.h>
#include <map>

namespace Security {

class DatabaseManager;
class DbContext;

// A class providing some of the base Database (DL and MDS) functionality.
class DatabaseSession: public DLAbstractPluginSession, public Allocator
{
public:
    DatabaseSession(DatabaseManager &inDatabaseManager);
    virtual ~DatabaseSession();

    virtual void GetDbNames(CSSM_NAME_LIST_PTR &NameList);
    virtual void FreeNameList(CSSM_NAME_LIST &NameList);
    void DbDelete(const char *DbName,
                  const CSSM_NET_ADDRESS *DbLocation,
                  const AccessCredentials *AccessCred);
    void DbCreate(const char *DbName,
                  const CSSM_NET_ADDRESS *DbLocation,
                  const CSSM_DBINFO &DBInfo,
                  CSSM_DB_ACCESS_TYPE AccessRequest,
                  const CSSM_RESOURCE_CONTROL_CONTEXT *CredAndAclEntry,
                  const void *OpenParameters,
                  CSSM_DB_HANDLE &DbHandle);
    virtual void DbOpen(const char *DbName,
                const CSSM_NET_ADDRESS *DbLocation,
                CSSM_DB_ACCESS_TYPE AccessRequest,
                const AccessCredentials *AccessCred,
                const void *OpenParameters,
                CSSM_DB_HANDLE &DbHandle);
    void DbClose(CSSM_DB_HANDLE DBHandle);
    void CreateRelation(CSSM_DB_HANDLE DBHandle,
                        CSSM_DB_RECORDTYPE RelationID,
                        const char *RelationName,
                        uint32 NumberOfAttributes,
                        const CSSM_DB_SCHEMA_ATTRIBUTE_INFO *pAttributeInfo,
                        uint32 NumberOfIndexes,
                        const CSSM_DB_SCHEMA_INDEX_INFO &pIndexInfo);
    void DestroyRelation(CSSM_DB_HANDLE DBHandle,
                         CSSM_DB_RECORDTYPE RelationID);

    void Authenticate(CSSM_DB_HANDLE DBHandle,
                      CSSM_DB_ACCESS_TYPE AccessRequest,
                      const AccessCredentials &AccessCred);
    void GetDbAcl(CSSM_DB_HANDLE DBHandle,
                  const CSSM_STRING *SelectionTag,
                  uint32 &NumberOfAclInfos,
                  CSSM_ACL_ENTRY_INFO_PTR &AclInfos);
    void ChangeDbAcl(CSSM_DB_HANDLE DBHandle,
                     const AccessCredentials &AccessCred,
                     const CSSM_ACL_EDIT &AclEdit);
    void GetDbOwner(CSSM_DB_HANDLE DBHandle,
                    CSSM_ACL_OWNER_PROTOTYPE &Owner);
    void ChangeDbOwner(CSSM_DB_HANDLE DBHandle,
                       const AccessCredentials &AccessCred,
                       const CSSM_ACL_OWNER_PROTOTYPE &NewOwner);
    void GetDbNameFromHandle(CSSM_DB_HANDLE DBHandle,
                             char **DbName);
    void DataInsert(CSSM_DB_HANDLE DBHandle,
                    CSSM_DB_RECORDTYPE RecordType,
                    const CSSM_DB_RECORD_ATTRIBUTE_DATA *Attributes,
                    const CssmData *Data,
                    CSSM_DB_UNIQUE_RECORD_PTR &UniqueId);
    void DataDelete(CSSM_DB_HANDLE DBHandle,
                    const CSSM_DB_UNIQUE_RECORD &UniqueRecordIdentifier);
    void DataModify(CSSM_DB_HANDLE DBHandle,
                    CSSM_DB_RECORDTYPE RecordType,
                    CSSM_DB_UNIQUE_RECORD &UniqueRecordIdentifier,
                    const CSSM_DB_RECORD_ATTRIBUTE_DATA *AttributesToBeModified,
                    const CssmData *DataToBeModified,
                    CSSM_DB_MODIFY_MODE ModifyMode);
    CSSM_HANDLE DataGetFirst(CSSM_DB_HANDLE DBHandle,
                             const CssmQuery *Query,
                             CSSM_DB_RECORD_ATTRIBUTE_DATA_PTR Attributes,
                             CssmData *Data,
                             CSSM_DB_UNIQUE_RECORD_PTR &UniqueId);
    bool DataGetNext(CSSM_DB_HANDLE DBHandle,
                     CSSM_HANDLE ResultsHandle,
                     CSSM_DB_RECORD_ATTRIBUTE_DATA_PTR Attributes,
                     CssmData *Data,
                     CSSM_DB_UNIQUE_RECORD_PTR &UniqueId);
    void DataAbortQuery(CSSM_DB_HANDLE DBHandle,
                        CSSM_HANDLE ResultsHandle);
    void DataGetFromUniqueRecordId(CSSM_DB_HANDLE DBHandle,
                                   const CSSM_DB_UNIQUE_RECORD &UniqueRecord,
                                   CSSM_DB_RECORD_ATTRIBUTE_DATA_PTR Attributes,
                                   CssmData *Data);
    void FreeUniqueRecord(CSSM_DB_HANDLE DBHandle,
                          CSSM_DB_UNIQUE_RECORD &UniqueRecord);
    void PassThrough(CSSM_DB_HANDLE DBHandle,
                     uint32 PassThroughId,
                     const void *InputParams,
                     void **OutputParams);

    DatabaseManager &mDatabaseManager;
protected:
    void closeAll();
private:
    CSSM_DB_HANDLE insertDbContext(DbContext &dbContext);
    DbContext &findDbContext(CSSM_DB_HANDLE inDbHandle);

    typedef std::map<CSSM_DB_HANDLE, DbContext *> DbContextMap;
    DbContextMap mDbContextMap;
    Mutex mDbContextMapLock;
};

} // end namespace Security

#endif //_H_DATABASESESSION
