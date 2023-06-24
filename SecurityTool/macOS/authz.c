/*
 * Copyright (c) 2003-2004,2006-2007,2009-2010,2012-2014 Apple Inc. All Rights Reserved.
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
 *
 *  authz.c
 */

#include <getopt.h>
#include <stdio.h>
#include <Security/AuthorizationPriv.h>
#include <utilities/SecCFRelease.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <os/log.h>

#include "authz.h"
#include "security_tool.h"
#include "fvunlock.h"

static AuthorizationRef
read_auth_ref_from_stdin(void)
{
	AuthorizationRef auth_ref = NULL;
	AuthorizationExternalForm extform;
	ssize_t bytes_read;

	while (kAuthorizationExternalFormLength != (bytes_read = read(STDIN_FILENO, &extform, kAuthorizationExternalFormLength)))
	{
		if ((bytes_read == -1) && ((errno != EAGAIN) || (errno != EINTR)))
			break;
	}
	if (bytes_read != kAuthorizationExternalFormLength)
		fprintf(stderr, "ERR: Failed to read authref\n");
	else
		if (AuthorizationCreateFromExternalForm(&extform, &auth_ref))
			fprintf(stderr, "ERR: Failed to internalize authref\n");

	close(0);

	return auth_ref;
}

static int
write_auth_ref_to_stdout(AuthorizationRef auth_ref)
{
	AuthorizationExternalForm extform;
	ssize_t bytes_written;

	if (AuthorizationMakeExternalForm(auth_ref, &extform))
		return -1;

	while (kAuthorizationExternalFormLength != (bytes_written = write(STDOUT_FILENO, &extform, kAuthorizationExternalFormLength)))
	{
		if ((bytes_written == -1) && ((errno != EAGAIN) || (errno != EINTR)))
			break;
	}

	if (bytes_written == kAuthorizationExternalFormLength)
		return 0;

	return -1;
}

static OSStatus
reset_database(const char *volumeUUID)
{
    os_log_debug(OS_LOG_DEFAULT, "Verifying volume %s", volumeUUID);
    OSStatus status = verifyVolume(volumeUUID);
    if (status != noErr) {
        return status;
    }
    
    os_log_debug(OS_LOG_DEFAULT, "Recovery setup in progress");
    status = recoverySetup();
    if (status != noErr) {
        return status;
    }
    
    return fvUnlockWriteResetDb(volumeUUID);
}

static void
write_dict_to_stdout(CFDictionaryRef dict)
{
	if (!dict)
		return;

	CFDataRef right_definition_xml = CFPropertyListCreateXMLData(NULL, dict);

	if (!right_definition_xml)
		return;

	write(STDOUT_FILENO, CFDataGetBytePtr(right_definition_xml), CFDataGetLength(right_definition_xml));
	CFRelease(right_definition_xml);
}

static CFDictionaryRef CF_RETURNS_RETAINED
read_dict_from_stdin(void)
{
	ssize_t bytes_read = 0;
	uint8_t buffer[4096];
	CFMutableDataRef data = CFDataCreateMutable(kCFAllocatorDefault, 0);
	CFErrorRef err = NULL;

	if (!data)
		return NULL;

	while ((bytes_read = read(STDIN_FILENO, (void *)buffer, sizeof(buffer))))
	{
		if (bytes_read == -1)
			break;
		else
			CFDataAppendBytes(data, buffer, bytes_read);
	}

	CFDictionaryRef right_dict = (CFDictionaryRef)CFPropertyListCreateWithData(kCFAllocatorDefault, data, kCFPropertyListImmutable, NULL, &err);
	CFRelease(data);

	if (NULL == right_dict) {
		CFShow(err);
		return NULL;
	}

	if (CFGetTypeID(right_dict) != CFDictionaryGetTypeID())
	{
		fprintf(stderr, "This is not a dictionary.\n");
		CFRelease(right_dict);
		return NULL;
	}
	return right_dict;
}

static CFPropertyListRef CF_RETURNS_RETAINED
read_plist_from_file(CFStringRef filePath)
{
	CFTypeRef         property = NULL;
	CFPropertyListRef propertyList = NULL;
	CFURLRef          fileURL = NULL;
	CFErrorRef       errorString = NULL;
	CFDataRef         resourceData = NULL;
	Boolean           status = FALSE;
	SInt32            errorCode = -1;

	// Convert the path to a URL.
	fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, filePath, kCFURLPOSIXPathStyle, false);
	if (NULL == fileURL) {
		goto bail;
	}
	property = CFURLCreatePropertyFromResource(kCFAllocatorDefault, fileURL, kCFURLFileExists, NULL);
	if (NULL == property) {
		goto bail;
	}
	status = CFBooleanGetValue(property);
	if (!status) {
		fprintf(stderr, "The file does not exist.\n");
		goto bail;
	}

	// Read the XML file.
	status = CFURLCreateDataAndPropertiesFromResource(kCFAllocatorDefault, fileURL, &resourceData, NULL, NULL, &errorCode);
	if (!status) {
		fprintf(stderr, "Error (%d) reading the file.\n", (int)errorCode);
		goto bail;
	}

	// Reconstitute the dictionary using the XML data.
	propertyList = CFPropertyListCreateWithData(kCFAllocatorDefault, resourceData, kCFPropertyListImmutable, NULL, &errorString);
	if (NULL == propertyList) {
		CFShow(errorString);
		goto bail;
	}

	// Some error checking.
	if (!CFPropertyListIsValid(propertyList, kCFPropertyListXMLFormat_v1_0) || CFGetTypeID(propertyList) != CFDictionaryGetTypeID()) {
		fprintf(stderr, "The file is invalid.\n");
		CFRelease(propertyList);
		propertyList = NULL;
		goto bail;
	}

bail:
	if (NULL != fileURL)
		CFRelease(fileURL);
	if (NULL != property)
		CFRelease(property);
	if (NULL != resourceData)
		CFRelease(resourceData);

	return propertyList;
}

static Boolean
write_plist_to_file(CFPropertyListRef propertyList, CFStringRef filePath)
{
	CFTypeRef   property = NULL;
	CFURLRef	fileURL = NULL;
	CFDataRef	xmlData = NULL;
	Boolean		status = FALSE;
	SInt32		errorCode = -1;
	CFErrorRef	errorRef = NULL;

	// Convert the path to a URL.
	fileURL = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, filePath, kCFURLPOSIXPathStyle, false);
	if (NULL == fileURL) {
		goto bail;
	}
	property = CFURLCreatePropertyFromResource(kCFAllocatorDefault, fileURL, kCFURLFileExists, NULL);
	if (NULL == property) {
		goto bail;
	}
	if (!CFBooleanGetValue(property)) {
		fprintf(stderr, "The file does not exist.\n");
		goto bail;
	}

	// Convert the property list into XML data.
	xmlData = CFPropertyListCreateData(kCFAllocatorDefault, propertyList, kCFPropertyListXMLFormat_v1_0, 0, &errorRef);
	if (errorRef) {
		fprintf(stderr, "The file could not be written.\n");
		goto bail;
	}

	// Write the XML data to the file.
	if (!CFURLWriteDataAndPropertiesToResource(fileURL, xmlData, NULL, &errorCode)) {
		fprintf(stderr, "The file could not be written.\n");
		goto bail;
	}

	status = TRUE;
bail:
    CFReleaseNull(property);
	if (NULL != xmlData)
		CFRelease(xmlData);
	if (NULL != fileURL)
		CFRelease(fileURL);

	return status;
}

static pid_t get_authd_pid(void)
{
    int n = proc_listpids(PROC_ALL_PIDS, 0, NULL, 0);
    
    int *buffer = (int *)malloc(sizeof(int)*n);
    int count = proc_listpids(PROC_ALL_PIDS, 0, buffer, n*sizeof(int));

    for (int i = 0; i < count; i++) {
        int pid = buffer[i];
        if (pid == 0) {
            continue;
        }
        char path[PATH_MAX + 1];
        if (proc_pidpath(pid, &path, PATH_MAX)) {
            if (strcmp(path, "/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/authd") == 0) {
                free(buffer);
                return pid;
            }
        }
    }
    free(buffer);
    return 0;
}

int
authorizationdb(int argc, char * const * argv)
{
	AuthorizationRef auth_ref = NULL;
	int ch;
    while ((ch = getopt(argc, argv, "i")) != -1)
	{
		switch  (ch)
		{
		case 'i':
			auth_ref = read_auth_ref_from_stdin();
			break;
		case '?':
		default:
			return SHOW_USAGE_MESSAGE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		return SHOW_USAGE_MESSAGE; // required right parameter(s)

    OSStatus status = errAuthorizationDenied;

    if (!strcmp("reset", argv[0]))
    {
        if (!isInFVUnlock())
        {
            os_log_debug(OS_LOG_DEFAULT, "Live reset command requested");

            if (geteuid() != 0)
            {
                fprintf(stderr, "This operation must be done as root\n");
                return -1;
            }
            status = remove("/var/db/auth.db");
            if (status)
            {
                fprintf(stderr, "Authorization Database reset failed: %d\n", status);
                return -1;
            }
            pid_t authdPid = get_authd_pid();
            if (authdPid > 0)
            {
                os_log_debug(OS_LOG_DEFAULT, "Restarting authd [%d]", authdPid);
                kill(authdPid, SIGQUIT);
            }
            printf("Authorization Database was reset\n");
        }
        else
        {
            os_log_debug(OS_LOG_DEFAULT, "Recovery reset command requested: %d", argc);
            if (argc == 2)
            {
                status = reset_database(argv[1]);
            }
            else
            {
                return SHOW_USAGE_MESSAGE;
            }
        }
    }
	else if (argc > 1)
	{
        if (!auth_ref && AuthorizationCreate(NULL, NULL, 0, &auth_ref))
        {
            os_log_debug(OS_LOG_DEFAULT, "Unable to create AuthorizationRef");
            return -1;
        }

		if (!strcmp("read", argv[0]))
		{
			CFDictionaryRef right_definition;
			status = AuthorizationRightGet(argv[1], &right_definition);
			if (!status)
			{
				write_dict_to_stdout(right_definition);
				CFRelease(right_definition);
			}
		}
		else if (!strcmp("write", argv[0]))
		{
			if (argc == 2)
			{
				CFDictionaryRef right_definition = read_dict_from_stdin();
				if (!right_definition)
                {
                    fprintf(stderr, "Unable to read the right definition\n");
                    os_log_error(OS_LOG_DEFAULT, "Unable to read the right definition");
                    return -1;
                }
				status = AuthorizationRightSet(auth_ref, argv[1], right_definition, NULL, NULL, NULL);
				CFRelease(right_definition);
			}
			else if (argc == 3)
			{
				// argv[2] is shortcut string
				CFStringRef shortcut_definition = CFStringCreateWithCStringNoCopy(NULL, argv[2], kCFStringEncodingUTF8, kCFAllocatorNull);
                if (!shortcut_definition)
                {
                    fprintf(stderr, "The provided right definition is invalid\n");
                    os_log_error(OS_LOG_DEFAULT, "Invalid right definition");
                    return -1;
                }
				status = AuthorizationRightSet(auth_ref, argv[1], shortcut_definition, NULL, NULL, NULL);
				CFRelease(shortcut_definition);
			}
			else
				return SHOW_USAGE_MESSAGE; // take one optional argument - no more
        }
        else if (!strcmp("remove", argv[0]))
		{
			status = AuthorizationRightRemove(auth_ref, argv[1]);
		}
    }
    else
    {
        return SHOW_USAGE_MESSAGE;
    }

	if (auth_ref)
		AuthorizationFree(auth_ref, 0);

	if (!do_quiet)
		fprintf(stderr, "%s (%d)\n", status ? "NO" : "YES", (int)status);

    if (status) {
        os_log_error(OS_LOG_DEFAULT, "Write command status: %d", (int)status);
        return -1;
    }
	return 0;
}

int
authorize(int argc, char * const *argv)
{
	int ch;
    int retval = 1;
	OSStatus status;

	Boolean user_interaction_allowed = FALSE, extend_rights = TRUE;
	Boolean partial_rights = FALSE, destroy_rights = FALSE;
	Boolean pre_authorize = FALSE, internalize = FALSE, externalize = FALSE;
	Boolean wait = FALSE, explicit_credentials = FALSE;
	Boolean isolate_explicit_credentials = FALSE, least_privileged = FALSE;
	char *login = NULL;

    while ((ch = getopt(argc, argv, "ucC:EpdPieqwxl")) != -1)
	{
		switch  (ch)
		{
		case 'u':
			user_interaction_allowed = TRUE;
			break;
		case 'c':
			explicit_credentials = TRUE;
			break;
		case 'C':
			explicit_credentials = TRUE;
			login = optarg;
			break;
		case 'e':
			externalize = TRUE;
			break;
		case 'E':
			extend_rights = FALSE;
			break;
		case 'p':
			partial_rights = TRUE;
			break;
		case 'd':
			destroy_rights = TRUE;
			break;
		case 'P':
			pre_authorize = TRUE;
			break;
		case 'i':
			internalize = TRUE;
			break;
		case 'w':
			wait = TRUE;
			externalize = TRUE;
			break;
		case 'x':
			isolate_explicit_credentials = TRUE;
			break;
		case 'l':
			least_privileged = TRUE;
			break;
		case '?':
		default:
			return SHOW_USAGE_MESSAGE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		return SHOW_USAGE_MESSAGE; // required right parameter(s)

// set up AuthorizationFlags
	AuthorizationFlags flags = kAuthorizationFlagDefaults |
		(user_interaction_allowed ? kAuthorizationFlagInteractionAllowed : 0) |
		(extend_rights ? kAuthorizationFlagExtendRights : 0) |
		(partial_rights ? kAuthorizationFlagPartialRights : 0) |
		(pre_authorize ? kAuthorizationFlagPreAuthorize : 0) |
		(least_privileged ? kAuthorizationFlagLeastPrivileged : 0);

// set up AuthorizationRightSet
	AuthorizationItem *rights = malloc(argc * sizeof(AuthorizationItem));
    if (!rights) {
        fprintf(stderr, "Out of memory\n");
        retval = 1;
        goto bail;
    }
	memset(rights, '\0', argc * sizeof(AuthorizationItem));
	AuthorizationItemSet rightset = { argc, rights };
	while (argc > 0)
		rights[--argc].name = *argv++;

	AuthorizationRef auth_ref = NULL;

// internalize AuthorizationRef
	if (internalize)
	{
		auth_ref = read_auth_ref_from_stdin();
        if (!auth_ref) {
            retval = 1;
            goto bail;
        }
	}

	if (!auth_ref && AuthorizationCreate(NULL, NULL,
				(least_privileged ? kAuthorizationFlagLeastPrivileged : 0),
                &auth_ref)) {
        retval = -1;
        goto bail;
    }

// prepare environment if needed
	AuthorizationEnvironment *envp = NULL;
	if (explicit_credentials) {
		if (!login)
			login = getlogin();
		char *pass = getpass("Password:");
        if (!(login && pass)) {
            retval = 1;
            goto bail;
        }
		static AuthorizationItem authenv[] = {
			{ kAuthorizationEnvironmentUsername },
			{ kAuthorizationEnvironmentPassword },
			{ kAuthorizationEnvironmentShared }			// optional (see below)
		};
		static AuthorizationEnvironment env = { 0, authenv };
		authenv[0].valueLength = strlen(login);
		authenv[0].value = login;
		authenv[1].valueLength = strlen(pass);
		authenv[1].value = pass;
		if (isolate_explicit_credentials)
			env.count = 2;		// do not send kAuthorizationEnvironmentShared
		else
			env.count = 3;		// do send kAuthorizationEnvironmentShared
		envp = &env;
	}

// perform Authorization
	AuthorizationRights *granted_rights = NULL;
	status = AuthorizationCopyRights(auth_ref, &rightset, envp, flags, &granted_rights);

// externalize AuthorizationRef
	if (externalize)
		write_auth_ref_to_stdout(auth_ref);

	if (!do_quiet)
		fprintf(stderr, "%s (%d) ", status ? "NO" : "YES", (int)status);

	if (!do_quiet && !status && granted_rights)
	{
		uint32_t index;
		fprintf(stderr, "{ %d: ", (int)granted_rights->count);
		for (index = 0; index < granted_rights->count; index++)
		{
			fprintf(stderr, "\"%s\"%s %c ", granted_rights->items[index].name,
				(kAuthorizationFlagCanNotPreAuthorize & granted_rights->items[index].flags) ? " (cannot-preauthorize)" : "",
				(index+1 != granted_rights->count) ? ',' : '}');
		}
		AuthorizationFreeItemSet(granted_rights);
	}

	if (!do_quiet)
		fprintf(stderr, "\n");

// wait for client to pick up AuthorizationRef
	if (externalize && wait)
		while (-1 != write(STDOUT_FILENO, NULL, 0))
			usleep(100);

// drop AuthorizationRef
	if (auth_ref)
		AuthorizationFree(auth_ref, destroy_rights ? kAuthorizationFlagDestroyRights : 0);

    retval = (status ? -1 : 0);
bail:
    if (rights) {
        free(rights);
    }

    return retval;
}


int
execute_with_privileges(int argc, char * const *argv)
{
	AuthorizationRef auth_ref = NULL;
	int ch;
    while ((ch = getopt(argc, argv, "i")) != -1)
	{
		switch  (ch)
		{
		case 'i':
			auth_ref = read_auth_ref_from_stdin();
			break;
		case '?':
		default:
			return SHOW_USAGE_MESSAGE;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc == 0)
		return SHOW_USAGE_MESSAGE; // required tool parameter(s)

	OSStatus status;

	if (!auth_ref && AuthorizationCreate(NULL, NULL, 0, &auth_ref))
		return -1;

	FILE *communications_pipe = NULL;

	status = AuthorizationExecuteWithPrivileges(auth_ref,argv[0], 0, (argc > 1) ? &argv[1] : NULL, &communications_pipe);

	if (!do_quiet)
		fprintf(stderr, "%s (%d) ", status ? "NO" : "YES", (int)status);

	if (!status)
	{
		ssize_t bytes_read = 0;
		uint8_t buffer[4096];

		while ((bytes_read = read(STDIN_FILENO, &buffer, sizeof(buffer))))
		{
			if ((bytes_read == -1) && ((errno != EAGAIN) || (errno != EINTR)))
				break;
			else
				while ((-1 == write(fileno(communications_pipe), buffer, bytes_read)) &&
						((errno == EAGAIN) || (errno == EINTR)))
							usleep(100);
		}
	}

	return (status ? -1 : 0);
}

