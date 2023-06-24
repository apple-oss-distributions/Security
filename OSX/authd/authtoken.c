/* Copyright (c) 2012-2013 Apple Inc. All Rights Reserved. */

#include "authtoken.h"
#include "authd_private.h"
#include "process.h"
#include "authitems.h"
#include "debugging.h"
#include "authutilities.h"
#include "server.h"

#include <CommonCrypto/CommonRandomSPI.h>
#include <Security/Authorization.h>
#include <Security/SecBase.h>
#include <sandbox.h>

#include <security_utilities/simulatecrash_assert.h>

AUTHD_DEFINE_LOG

static uint64_t global_auth_count;


static Boolean AuthTokenEqualCallBack(const void *value1, const void *value2)
{
    return (*(uint64_t*)value1) == (*(uint64_t*)value2);
}

static CFHashCode AuthTokenHashCallBack(const void *value)
{
//    CFHashCode hash;
//    AuthorizationBlob* blob = (AuthorizationBlob*)value;
//    hash = blob->data[1];
//    hash <<= 32;
//    hash |= blob->data[0];
//    return hash;
    //quick 64 bit aligned version
    return *((CFHashCode*)((AuthorizationBlob*)value)->data);
}

const CFDictionaryKeyCallBacks kAuthTokenKeyCallBacks = {
    .version = 0,
    .retain = NULL,
    .release = NULL,
    .copyDescription = NULL,
    .equal = &AuthTokenEqualCallBack,
    .hash = &AuthTokenHashCallBack
};

struct _auth_token_s {
    __AUTH_BASE_STRUCT_HEADER__;
    
    AuthorizationBlob blob;
    auth_token_state_t state;
    audit_info_s auditInfo;
    dispatch_queue_t dispatch_queue;
    
    CFMutableSetRef processes;
    
    session_t session;
    process_t creator; // weak reference, used for entitlement checking
    mach_port_t creator_bootstrap_port;
    
    auth_items_t context;
    
    CFMutableSetRef credentials;
    CFMutableSetRef authorized_rights;

	CFMutableDataRef encryption_key;
    
    bool least_privileged;
    bool appleSigned;
	bool firstPartySigned;
    
    bool sandboxed;
    char * code_url;
    
    uint64_t auth_index;
    
    credential_t credential;
};

static void
_auth_token_finalize(CFTypeRef value)
{
    auth_token_t auth = (auth_token_t)value;
    os_log_debug(AUTHD_LOG, "authtoken: auth %llu finalizing", auth->auth_index);
    
    dispatch_barrier_sync(auth->dispatch_queue, ^{});
    
    dispatch_release(auth->dispatch_queue);
    CFReleaseNull(auth->session);
    CFReleaseNull(auth->processes);
    CFReleaseNull(auth->context);
    CFReleaseNull(auth->credentials);
    CFReleaseNull(auth->authorized_rights);
    free_safe(auth->code_url);
    CFReleaseNull(auth->credential);
	CFReleaseNull(auth->encryption_key);
    
    if (auth->creator_bootstrap_port != MACH_PORT_NULL) {
        mach_port_deallocate(mach_task_self(), auth->creator_bootstrap_port);
		auth->creator_bootstrap_port = MACH_PORT_NULL;
    }
}

static Boolean
_auth_token_equal(CFTypeRef value1, CFTypeRef value2)
{
    auth_token_t auth1 = (auth_token_t)value1;
    auth_token_t auth2 = (auth_token_t)value2;
    
    return memcmp(&auth1->blob, &auth2->blob, sizeof(AuthorizationBlob)) == 0;
}

static CFStringRef
_auth_token_copy_description(CFTypeRef value)
{
    auth_token_t auth = (auth_token_t)value;
    return CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("auth_token: uid=%i, pid=%i, processes=%li least_privileged=%i"),
                                    auth->auditInfo.euid, auth->auditInfo.pid, CFSetGetCount(auth->processes), auth->least_privileged);
}

static CFHashCode
_auth_token_hash(CFTypeRef value)
{
    auth_token_t auth = (auth_token_t)value;
    return *(CFHashCode*)&auth->blob;
}

AUTH_TYPE_INSTANCE(auth_token,
                   .init = NULL,
                   .copy = NULL,
                   .finalize = _auth_token_finalize,
                   .equal = _auth_token_equal,
                   .hash = _auth_token_hash,
                   .copyFormattingDesc = NULL,
                   .copyDebugDesc = _auth_token_copy_description
                   );

static CFTypeID auth_token_get_type_id(void) {
    static CFTypeID type_id = _kCFRuntimeNotATypeID;
    static dispatch_once_t onceToken;
    
    dispatch_once(&onceToken, ^{
        type_id = _CFRuntimeRegisterClass(&_auth_type_auth_token);
    });
    
    return type_id;
}

static auth_token_t
_auth_token_create(const audit_info_s * auditInfo, bool operateAsLeastPrivileged)
{
#if __LLP64__
    __Check_Compile_Time(sizeof(CFHashCode) == sizeof(AuthorizationBlob));
#endif
    
    auth_token_t auth = (auth_token_t)_CFRuntimeCreateInstance(kCFAllocatorDefault, auth_token_get_type_id(), AUTH_CLASS_SIZE(auth_token), NULL);
    require(auth != NULL, done);
    
    if (CCRandomCopyBytes(kCCRandomDefault, auth->blob.data, sizeof(auth->blob.data)) != kCCSuccess) {
        os_log_error(AUTHD_LOG, "authtoken: failed to generate blob (PID %d)", auditInfo->pid);
        CFReleaseNull(auth);
        goto done;
    }
    auth->auth_index = global_auth_count++;
    
    auth->context = auth_items_create();
    auth->auditInfo = *auditInfo;
    auth->least_privileged = operateAsLeastPrivileged;

    auth->dispatch_queue = dispatch_queue_create(NULL, DISPATCH_QUEUE_SERIAL);
    check(auth->dispatch_queue != NULL);
    
    auth->credentials = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
    auth->authorized_rights = CFSetCreateMutable(kCFAllocatorDefault, 0, &kCFTypeSetCallBacks);
    auth->processes = CFSetCreateMutable(kCFAllocatorDefault, 0, NULL);
    auth->creator_bootstrap_port = MACH_PORT_NULL;

    if (sandbox_check_by_audit_token(auth->auditInfo.opaqueToken, "authorization-right-obtain", SANDBOX_CHECK_NO_REPORT) != 0)
		auth->sandboxed = true;
	else
		auth->sandboxed = false;
    
	size_t key_length = kCCKeySizeAES256;
	auth->encryption_key = CFDataCreateMutable(kCFAllocatorDefault, key_length);
	if (auth->encryption_key) {
		int rv = CCRandomCopyBytes(kCCRandomDefault, CFDataGetMutableBytePtr(auth->encryption_key), key_length);
		if (rv != kCCSuccess) {
			CFReleaseNull(auth->encryption_key)
		}
		CFDataSetLength(auth->encryption_key, key_length);
	}

#if DEBUG
    CFHashCode code = AuthTokenHashCallBack(&auth->blob);
    if (memcmp(&code, auth->blob.data, sizeof(auth->blob.data)) != 0) {
        os_log_debug(AUTHD_LOG, "authtoken[%i]: blob = %x%01x", auth->auditInfo.pid, auth->blob.data[1], auth->blob.data[0]);
        os_log_debug(AUTHD_LOG, "authtoken[%i]: hash = %lx", auth->auditInfo.pid, code);
        assert(false);
    }
#endif
    
done:
    return auth;
}

auth_token_t
auth_token_create(process_t proc, bool operateAsLeastPrivileged)
{
    auth_token_t auth = NULL;
    require(proc != NULL, done);
    
    auth = _auth_token_create(process_get_audit_info(proc), operateAsLeastPrivileged);
    require(auth != NULL, done);
    
    auth->creator = proc;
    auth->session = (session_t)CFRetain(process_get_session(proc));
    auth->code_url = _copy_string(process_get_code_url(proc));
    auth->appleSigned = process_apple_signed(proc);
    auth->creator_bootstrap_port = process_get_bootstrap(proc);
    // This line grabs a reference to the send right to the bootstrap (our right to send to the bootstrap)
    // This makes it critical to use the same call in reverse as we are only getting a ref to one right,
    // but deallocate will free a ref to all 5 rights.
    if (auth->creator_bootstrap_port != MACH_PORT_NULL) {
        kern_return_t error_code = mach_port_mod_refs(mach_task_self(), auth->creator_bootstrap_port, MACH_PORT_RIGHT_SEND, 1);
        if (error_code != KERN_SUCCESS) {
            // If no reference to the mach port right can be obtained, we don't hold the copy, so mark it NULL again!
            auth->creator_bootstrap_port = MACH_PORT_NULL;
        }
    }
    
    os_log_debug(AUTHD_LOG, "authtoken: created auth %llu (PID %d)", auth->auth_index, auth->auditInfo.pid);

done:
    return auth;
}

bool
auth_token_get_sandboxed(auth_token_t auth)
{
    return auth->sandboxed;
}

const char *
auth_token_get_code_url(auth_token_t auth)
{
    return auth->code_url;
}

const void *
auth_token_get_key(auth_token_t auth)
{
    return &auth->blob;
}

auth_items_t
auth_token_get_context(auth_token_t auth)
{
    return auth->context;
}

bool
auth_token_least_privileged(auth_token_t auth)
{
    return auth->least_privileged;
}

uid_t
auth_token_get_uid(auth_token_t auth)
{
    assert(auth); // marked non-null
    return auth->auditInfo.euid;
}

pid_t
auth_token_get_pid(auth_token_t auth)
{
    assert(auth); // marked non-null
    return auth->auditInfo.pid;
}

session_t
auth_token_get_session(auth_token_t auth)
{
    return auth->session;
}

const AuthorizationBlob *
auth_token_get_blob(auth_token_t auth)
{
    return &auth->blob;
}

const audit_info_s *
auth_token_get_audit_info(auth_token_t auth)
{
    return &auth->auditInfo;
}

mach_port_t
auth_token_get_creator_bootstrap(auth_token_t auth)
{
    return auth->creator_bootstrap_port;
}

CFIndex
auth_token_add_process(auth_token_t auth, process_t proc)
{
    __block CFIndex count = 0;
    dispatch_sync(auth->dispatch_queue, ^{
        CFSetAddValue(auth->processes, proc);
        count = CFSetGetCount(auth->processes);
    });
    return count;
}

CFIndex
auth_token_remove_process(auth_token_t auth, process_t proc)
{
    __block CFIndex count = 0;
    dispatch_sync(auth->dispatch_queue, ^{
        if (auth->creator == proc) {
            auth->creator = NULL;
        }
        CFSetRemoveValue(auth->processes, proc);
        count = CFSetGetCount(auth->processes);
    });
    return count;
}

CFIndex
auth_token_get_process_count(auth_token_t auth)
{
    __block CFIndex count = 0;
    dispatch_sync(auth->dispatch_queue, ^{
        count = CFSetGetCount(auth->processes);
    });
    return count;
}

void
auth_token_set_credential(auth_token_t auth, credential_t cred)
{
    dispatch_sync(auth->dispatch_queue, ^{
        CFSetSetValue(auth->credentials, cred);
    });
}

bool
auth_token_credentials_iterate(auth_token_t auth, credential_iterator_t iter)
{
    __block bool result = false;
    
    dispatch_sync(auth->dispatch_queue, ^{
        CFIndex count = CFSetGetCount(auth->credentials);
        if (count > 128) { // <rdar://problem/38179345> Variable Length Arrays; AuthD
                           // auth_token usually contains 0 or 1 credential
            count = 128;
        }
        CFTypeRef values[count];
        CFSetGetValues(auth->credentials, values);
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

void
auth_token_set_right(auth_token_t auth, credential_t right)
{
    dispatch_sync(auth->dispatch_queue, ^{
        CFSetSetValue(auth->authorized_rights, right);
    });
}

CFTypeRef
auth_token_copy_entitlement_value(auth_token_t auth, const char * entitlement)
{
    __block CFTypeRef value = NULL;
    dispatch_sync(auth->dispatch_queue, ^{
        if (auth->creator) {
            value = process_copy_entitlement_value(auth->creator, entitlement);
        }
    });
    
    return value;
}

bool
auth_token_has_entitlement(auth_token_t auth, const char * entitlement)
{
    __block bool entitled = false;

    dispatch_sync(auth->dispatch_queue, ^{
        if (auth->creator) {
            entitled = process_has_entitlement(auth->creator, entitlement);
        }
    });
    os_log_debug(AUTHD_LOG, "authtoken: PID %d is%{public}s entitled for %{public}s", auth->auditInfo.pid, entitled ? "":" not", entitlement);

    return entitled;
}

bool
auth_token_has_entitlement_for_right(auth_token_t auth, const char * right)
{
    __block bool entitled = false;
    
    dispatch_sync(auth->dispatch_queue, ^{
        if (auth->creator) {
            entitled = process_has_entitlement_for_right(auth->creator, right);
        }
    });
    os_log_debug(AUTHD_LOG, "authtoken: PID %d is%{public}s entitled for right %{public}s", auth->auditInfo.pid, entitled ? "":" not", right);

    return entitled;
}

credential_t
auth_token_get_credential(auth_token_t auth)
{
    dispatch_sync(auth->dispatch_queue, ^{
        if (auth->credential == NULL) {
            auth->credential = credential_create(auth->auditInfo.euid);
        }
    });
    
    return auth->credential;
}

bool
auth_token_apple_signed(auth_token_t auth)
{
    return auth->appleSigned;
}

bool auth_token_is_creator(auth_token_t auth, process_t proc)
{
    assert(proc); // marked non-null
    __block bool creator = false;
    dispatch_sync(auth->dispatch_queue, ^{
        if (auth->creator == proc) {
            creator = true;
        }
    });
    return creator;
}

void auth_token_set_state(auth_token_t auth, auth_token_state_t state)
{
    auth->state |= state;
}

void auth_token_clear_state(auth_token_t auth, auth_token_state_t state)
{
    auth->state &= ~state;
}

auth_token_state_t auth_token_get_state(auth_token_t auth)
{
    return auth->state;
}

bool auth_token_check_state(auth_token_t auth, auth_token_state_t state)
{
    if (state) {
        return (auth->state & state) != 0;
    } else {
        return auth->state == 0;
    }
}

CFDataRef auth_token_get_encryption_key(auth_token_t auth)
{
	return auth->encryption_key;
}

uint64_t auth_token_get_index(auth_token_t auth)
{
    return auth->auth_index;
}
