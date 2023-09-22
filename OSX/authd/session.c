/* Copyright (c) 2012 Apple Inc. All Rights Reserved. */

#include "session.h"
#include "process.h"
#include "debugging.h"
#include <dispatch/dispatch.h>
#include <CoreFoundation/CoreFoundation.h>

#include <security_utilities/simulatecrash_assert.h>

AUTHD_DEFINE_LOG

struct _session_s {
    __AUTH_BASE_STRUCT_HEADER__;
    
    CFMutableSetRef credentials;
    CFMutableSetRef processes;
    auditinfo_addr_t auditinfo;
    
    dispatch_queue_t dispatch_queue;

};

static void
_session_finalize(CFTypeRef value)
{
    session_t session = (session_t)value;
    
    os_log_debug(AUTHD_LOG, "session: %i deallocated", session->auditinfo.ai_asid);
    
    // make sure queue is empty
    dispatch_barrier_sync(session->dispatch_queue, ^{});
    
    dispatch_release(session->dispatch_queue);
    CFReleaseNull(session->credentials);
    CFReleaseNull(session->processes);
}

AUTH_TYPE_INSTANCE(session,
                   .init = NULL,
                   .copy = NULL,
                   .finalize = _session_finalize,
                   .equal = NULL,
                   .hash = NULL,
                   .copyFormattingDesc = NULL,
                   .copyDebugDesc = NULL
                   );

static CFTypeID session_get_type_id(void) {
    static CFTypeID type_id = _kCFRuntimeNotATypeID;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        type_id = _CFRuntimeRegisterClass(&_auth_type_session);
    });
    
    return type_id;
}

session_t
session_create(session_id_t sid)
{
    session_t session = NULL;
        
    session = (session_t)_CFRuntimeCreateInstance(kCFAllocatorDefault, session_get_type_id(), AUTH_CLASS_SIZE(session), NULL);
    require(session != NULL, done);
    
    session->auditinfo.ai_asid = sid;
    
    if (!session_update(session)) {
        os_log_error(AUTHD_LOG, "session: failed to get session info");
    }
    
    session->dispatch_queue = dispatch_queue_create("Session queue", DISPATCH_QUEUE_SERIAL);
    check(session->dispatch_queue != NULL);
    
    session->credentials = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
    session->processes = CFSetCreateMutable(kCFAllocatorDefault, 0, NULL);
    
    os_log_debug(AUTHD_LOG, "session: %i created (uid=%i)", session->auditinfo.ai_asid, session->auditinfo.ai_auid);

done:
    return session;
}

bool session_update(session_t session)
{
    return auditon(A_GETSINFO_ADDR, &session->auditinfo, sizeof(session->auditinfo)) == 0;
}

uint64_t session_get_attributes(session_t session)
{
    session_update(session);
    
    return session->auditinfo.ai_flags;
}

static void _set_attributes(session_t session, uint64_t flags)
{
    session->auditinfo.ai_flags = flags;
    int32_t rc = setaudit_addr(&session->auditinfo, sizeof(session->auditinfo));
    if (rc != 0) {
        os_log_debug(AUTHD_LOG, "session: failed to update session info (%d)", rc);
    }
}

void session_set_attributes(session_t session, uint64_t flags)
{
    session_update(session);
    _set_attributes(session,session->auditinfo.ai_flags | flags);
}

void session_clear_attributes(session_t session, uint64_t flags)
{
    session_update(session);
    _set_attributes(session,session->auditinfo.ai_flags & ~flags);
}


const void *
session_get_key(session_t session)
{
    return &session->auditinfo.ai_asid;
}

session_id_t
session_get_id(session_t session)
{
    assert(session); // marked non-null
    return session->auditinfo.ai_asid;
}

uid_t
session_get_uid(session_t session)
{
    assert(session); // marked non-null
    return session->auditinfo.ai_auid;
}

CFIndex
session_add_process(session_t session, process_t proc)
{
    __block CFIndex count = 0;
    dispatch_sync(session->dispatch_queue, ^{
        CFSetAddValue(session->processes, proc);
        count = CFSetGetCount(session->processes);
    });
    return count;
}

CFIndex
session_remove_process(session_t session, process_t proc)
{
    __block CFIndex count = 0;
    dispatch_sync(session->dispatch_queue, ^{
        CFSetRemoveValue(session->processes, proc);
        count = CFSetGetCount(session->processes);
    });
    return count;
}

CFIndex
session_get_process_count(session_t session)
{
    __block CFIndex count = 0;
    dispatch_sync(session->dispatch_queue, ^{
        count = CFSetGetCount(session->processes);
    });
    return count;
}

void
session_set_credential(session_t session, credential_t cred)
{
    if (!credential_get_valid(cred))
        return;
    
    dispatch_sync(session->dispatch_queue, ^{
        CFSetSetValue(session->credentials, cred);
    });
}

void
session_credentials_purge(session_t session)
{
    session_credentials_iterate(session, ^bool(credential_t cred) {
        if (!credential_get_valid(cred)) {
            CFSetRemoveValue(session->credentials, cred);
        }
        return true;
    });
}

bool
session_credentials_iterate(session_t session, credential_iterator_t iter)
{
    __block bool result = false;
    
    dispatch_sync(session->dispatch_queue, ^{
        CFIndex count = CFSetGetCount(session->credentials);
        if (count > 128) { // <rdar://problem/38179345> Variable Length Arrays; AuthD
            // session usually contains 0 or 1 credential
            count = 128;
        }

        CFTypeRef values[count];
        CFSetGetValues(session->credentials, values);
        for (CFIndex i = 0; i < count; i++) {
            credential_t cred = (credential_t)values[i];
            result = iter(cred);
            if (!result) {
                break;
            }
        }
    });

    
    return result;
}
