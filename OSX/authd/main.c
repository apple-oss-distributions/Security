/* Copyright (c) 2012-2013 Apple Inc. All Rights Reserved. */

#include "debugging.h"
#include "server.h"
#include "process.h"
#include "session.h"
#include "authtoken.h"
#include "engine.h"
#include "authd_private.h"
#include "connection.h"

#include <Security/Authorization.h>

#include <xpc/xpc.h>
#include <xpc/private.h>
#include <dispatch/dispatch.h>
#include <security_utilities/simulatecrash_assert.h>
#include <sandbox.h>

#if DEBUG
#include <malloc/malloc.h>
#endif

AUTHD_DEFINE_LOG

static dispatch_queue_t
_get_server_xpc_queue(void)
{
    static dispatch_once_t onceToken;
    static dispatch_queue_t xpc_queue = NULL;
    
    dispatch_once(&onceToken, ^{
        dispatch_queue_attr_t attribute = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_CONCURRENT, QOS_CLASS_USER_INTERACTIVE, 0);
        if (attribute == NULL) {
            os_log_error(AUTHD_LOG, "Failed to create high-priority attribute");
        }
        xpc_queue = dispatch_queue_create("com.apple.security.auth.xpc", attribute);
        check(xpc_queue != NULL);
    });
    
    return xpc_queue;
}
#define ADD_CASE(item) case item: return #item;

static const char *_get_pri(qos_class_t pri, char *buffer, size_t buffsize)
{
    switch(pri) {
            ADD_CASE(QOS_CLASS_BACKGROUND)
            ADD_CASE(QOS_CLASS_UTILITY)
            ADD_CASE(QOS_CLASS_DEFAULT)
            ADD_CASE(QOS_CLASS_USER_INITIATED)
            ADD_CASE(QOS_CLASS_USER_INTERACTIVE)
            ADD_CASE(QOS_CLASS_UNSPECIFIED)
    }
    snprintf(buffer, buffsize, "%d", pri);
    return buffer;
}

static const char *_security_xpc_type_desc(uint64_t type)
{
    switch (type) {
            ADD_CASE(AUTHORIZATION_CREATE)
            ADD_CASE(AUTHORIZATION_CREATE_WITH_AUDIT_TOKEN)
            ADD_CASE(AUTHORIZATION_FREE)
            ADD_CASE(AUTHORIZATION_COPY_RIGHTS)
            ADD_CASE(AUTHORIZATION_COPY_INFO)
            ADD_CASE(AUTHORIZATION_MAKE_EXTERNAL_FORM)
            ADD_CASE(AUTHORIZATION_CREATE_FROM_EXTERNAL_FORM)
            ADD_CASE(AUTHORIZATION_RIGHT_GET)
            ADD_CASE(AUTHORIZATION_RIGHT_SET)
            ADD_CASE(AUTHORIZATION_RIGHT_REMOVE)
            ADD_CASE(SESSION_SET_USER_PREFERENCES)
            ADD_CASE(AUTHORIZATION_DISMISS)
            ADD_CASE(AUTHORIZATION_SETUP)
            ADD_CASE(AUTHORIZATION_COPY_RIGHT_PROPERTIES)
            ADD_CASE(AUTHORIZATION_COPY_PRELOGIN_USERDB)
            ADD_CASE(AUTHORIZATION_COPY_PRELOGIN_PREFS)
            ADD_CASE(AUTHORIZATION_PRELOGIN_SC_OVERRIDE)
            ADD_CASE(AUTHORIZATION_DEV)
    }
    return "Unrecognized request";
}

static void
security_auth_peer_event_handler(xpc_connection_t connection, xpc_object_t event)
{
    __block OSStatus status = errAuthorizationDenied;
    
    connection_t conn = (connection_t)xpc_connection_get_context(connection);
    require_action(conn != NULL, done, os_log_error(AUTHD_LOG, "xpc: process context not found"));

    CFRetainSafe(conn);

    xpc_type_t type = xpc_get_type(event);

	if (type == XPC_TYPE_ERROR) {
		if (event == XPC_ERROR_CONNECTION_INVALID) {
			// The client process on the other end of the connection has either
			// crashed or canceled the connection. After receiving this error,
			// the connection is in an invalid state, and you do not need to
			// call xpc_connection_cancel(). Just tear down any associated state
			// here.
            os_log_debug(AUTHD_LOG, "xpc: client disconnected PID %d", xpc_connection_get_pid(connection));
            connection_destroy_agents(conn);
		} else if (event == XPC_ERROR_TERMINATION_IMMINENT) {
			// Handle per-connection termination cleanup.
            os_log_debug(AUTHD_LOG, "xpc: per-connection termination PID %d", xpc_connection_get_pid(connection));
		}
	} else {
		assert(type == XPC_TYPE_DICTIONARY);
        
        xpc_object_t reply = xpc_dictionary_create_reply(event);
        require(reply != NULL, done);
        
        uint64_t auth_type = xpc_dictionary_get_uint64(event, AUTH_XPC_TYPE);
        char buffer[16];
        os_log_debug(AUTHD_LOG, "xpc: handling %s from PID %d pri %s", _security_xpc_type_desc(auth_type), xpc_connection_get_pid(connection), _get_pri(qos_class_self(), buffer, sizeof(*buffer)));

        switch (auth_type) {
            case AUTHORIZATION_CREATE:
                status = authorization_create(conn,event,reply);
                break;
            case AUTHORIZATION_CREATE_WITH_AUDIT_TOKEN:
                status = authorization_create_with_audit_token(conn,event,reply);
                break;
            case AUTHORIZATION_FREE:
                status = authorization_free(conn,event,reply);
                break;
            case AUTHORIZATION_COPY_RIGHTS:
                status = authorization_copy_rights(conn,event,reply);
                break;
            case AUTHORIZATION_COPY_INFO:
                status = authorization_copy_info(conn,event,reply);
                break;
            case AUTHORIZATION_MAKE_EXTERNAL_FORM:
                status = authorization_make_external_form(conn,event,reply);
                break;
            case AUTHORIZATION_CREATE_FROM_EXTERNAL_FORM:
                status = authorization_create_from_external_form(conn,event,reply);
                break;
            case AUTHORIZATION_RIGHT_GET:
                status = authorization_right_get(conn,event,reply);
                break;
            case AUTHORIZATION_RIGHT_SET:
                status = authorization_right_set(conn,event,reply);
                break;
            case AUTHORIZATION_RIGHT_REMOVE:
                status = authorization_right_remove(conn,event,reply);
                break;
            case SESSION_SET_USER_PREFERENCES:
                status = session_set_user_preferences(conn,event,reply);
                break;
            case AUTHORIZATION_DISMISS:
                connection_destroy_agents(conn);
                status = errAuthorizationSuccess;
                break;
            case AUTHORIZATION_SETUP:
                {
                    mach_port_t bootstrap = xpc_dictionary_copy_mach_send(event, AUTH_XPC_BOOTSTRAP);
                    if (!process_set_bootstrap(connection_get_process(conn), bootstrap)) {
                        if (bootstrap != MACH_PORT_NULL) {
                            mach_port_deallocate(mach_task_self(), bootstrap);
                        }
                    }
                }
                status = errAuthorizationSuccess;
                break;
			case AUTHORIZATION_COPY_RIGHT_PROPERTIES:
				status = authorization_copy_right_properties(conn,event,reply);
				break;
            case AUTHORIZATION_COPY_PRELOGIN_USERDB:
                status = authorization_copy_prelogin_userdb(conn,event,reply);
                break;
            case AUTHORIZATION_COPY_PRELOGIN_PREFS:
                status = authorization_copy_prelogin_pref_value(conn, event, reply);
                break;
            case AUTHORIZATION_PRELOGIN_SC_OVERRIDE:
                status = authorization_prelogin_smartcardonly_override(conn, event, reply);
                break;
#if DEBUG
            case AUTHORIZATION_DEV:
                server_dev();
                break;
#endif
            default:
                break;
        }

        xpc_dictionary_set_int64(reply, AUTH_XPC_STATUS, status);
        xpc_connection_send_message(connection, reply);
        xpc_release(reply);
	}

done:
    CFReleaseSafe(conn);
}

static void
connection_finalizer(void * conn)
{
    os_log_debug(AUTHD_LOG, "xpc: connection_finalizer for PID %d", connection_get_pid(conn));
    server_unregister_connection(conn);

//#if DEBUG
//    malloc_printf("-=-=-=- connection_finalizer() -=-=-=-\n");
//    malloc_zone_print(malloc_default_zone(), false);
//#endif
}

static void
security_auth_event_handler(xpc_connection_t xpc_conn)
{
    char buffer[16];
    os_log_debug(AUTHD_LOG, "xpc: incoming connection from PID %d pri %s", xpc_connection_get_pid(xpc_conn), _get_pri(qos_class_self(), buffer, sizeof(*buffer)));
    xpc_connection_set_target_queue(xpc_conn, _get_server_xpc_queue());
    connection_t conn = server_register_connection(xpc_conn);
    
    if (conn) {
        xpc_connection_set_context(xpc_conn, conn);
        xpc_connection_set_finalizer_f(xpc_conn, connection_finalizer);
        xpc_connection_set_event_handler(xpc_conn, ^(xpc_object_t event) {
            xpc_retain(xpc_conn);
            xpc_retain(event);
            dispatch_async(_get_server_xpc_queue(), ^{
                security_auth_peer_event_handler(xpc_conn, event);
                xpc_release(event);
                xpc_release(xpc_conn);
            });
        });
        xpc_connection_resume(xpc_conn);

    } else {
        os_log_error(AUTHD_LOG, "xpc: failed to register connection (PID %d)", xpc_connection_get_pid(xpc_conn));
        xpc_connection_cancel(xpc_conn);
    }
}

static void sandbox(const char *tmpdir)
{
    char 		*errorbuf;
	const char	*sandbox_params[] = {"TMP_DIR", tmpdir, "ENABLE_PATTERN_VARIABLES", "1", NULL};
    int32_t		rc;

	rc = sandbox_init_with_parameters(SECURITY_AUTH_NAME, SANDBOX_NAMED, sandbox_params, &errorbuf);
    if (rc) {
        os_log_error(AUTHD_LOG, "server: sandbox_init failed %{public}s (%i)", errorbuf, rc);
        sandbox_free_error(errorbuf);
#ifndef DEBUG
        abort();
#endif
    }
}

int main(int argc AUTH_UNUSED, const char *argv[] AUTH_UNUSED)
{
//#if DEBUG
//    malloc_printf("-=-=-=- main() -=-=-=-\n");
//    malloc_zone_print(malloc_default_zone(), false);
//#endif

	os_log_debug(AUTHD_LOG, "starting");

	// <rdar://problem/20900280> authd needs to provide a writeable temp dir for SQLite
	// <rdar://problem/21223798> Insecure temporary directory in authd (/tmp/authd)
	char	darwin_tmp[PATH_MAX];
	size_t	len = confstr(_CS_DARWIN_USER_TEMP_DIR, darwin_tmp, sizeof(darwin_tmp));
	if (len == 0 || len >= PATH_MAX) {
		os_log_error(AUTHD_LOG, "Invalid _CS_DARWIN_USER_TEMP_DIR");
		return errAuthorizationInternal;
	}

	char *real_tmp = realpath(darwin_tmp, NULL);
	if (real_tmp == NULL) {
		os_log_error(AUTHD_LOG, "realpath( %{public}s ) FAILED", darwin_tmp);
		return errAuthorizationInternal;
	}

	setenv("SQLITE_TMPDIR", real_tmp, 1);
    sandbox(real_tmp);
	free(real_tmp);

    if (server_init() != errAuthorizationSuccess) {
        os_log_error(AUTHD_LOG, "auth: server_init() failed");
        return errAuthorizationInternal;
    }
        
//#if DEBUG
//    malloc_printf("-=-=-=- server_init() -=-=-=-\n");
//    malloc_zone_print(malloc_default_zone(), false);
//#endif

    xpc_main(security_auth_event_handler);
    
    // xpc_main() will never return, but if it did, here's what you'd call:
    //server_cleanup();
    
	return 0;
}
