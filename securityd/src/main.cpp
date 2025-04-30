/*
 * Copyright (c) 2000-2009,2014 Apple Inc. All Rights Reserved.
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
// securityd - Apple security services daemon.
//
#include "server.h"
#include "session.h"
#include "notifications.h"
#include "auditevents.h"
#include "self.h"
#include "util.h"

#include <security_utilities/daemon.h>
#include <security_utilities/machserver.h>
#include <security_utilities/logging.h>

#include <Security/SecKeychainPriv.h>

#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <syslog.h>

// ACL subject types (their makers are instantiated here)
#include <security_cdsa_utilities/acl_any.h>
#include <security_cdsa_utilities/acl_password.h>
#include <security_cdsa_utilities/acl_prompted.h>
#include <security_cdsa_utilities/acl_protectedpw.h>
#include <security_cdsa_utilities/acl_threshold.h>
#include <security_cdsa_utilities/acl_codesigning.h>
#include <security_cdsa_utilities/acl_process.h>
#include <security_cdsa_utilities/acl_comment.h>
#include <security_cdsa_utilities/acl_preauth.h>
#include "acl_keychain.h"
#include "acl_partition.h"

#include <sandbox.h>

//
// Local functions of the main program driver
//
static void usage(const char *me) __attribute__((noreturn));
static void handleSignals(int sig);

static Port gMainServerPort;


//
// Main driver
//
int main(int argc, char *argv[])
{
	DisableLocalization();

	// clear the umask - we know what we're doing
	secnotice("SecServer", "starting umask was 0%o", ::umask(0));
	::umask(0);

	// tell the keychain (client) layer to turn off the server interface
	SecKeychainSetServerMode();

    const char *params[] = {"LEGACY_TOKENS_ENABLED", "NO", NULL};
    char* errorbuf = NULL;
    if (sandbox_init_with_parameters("com.apple.securityd", SANDBOX_NAMED, params, &errorbuf)) {
        seccritical("SecServer: unable to enter sandbox: %{public}s", errorbuf);
        if (errorbuf) {
            sandbox_free_error(errorbuf);
        }
        exit(1);
    } else {
        secnotice("SecServer", "entered sandbox");
    }

	// program arguments (preset to defaults)
	bool debugMode = false;
	int workerTimeout = 0;
	int maxThreads = 0;
	bool waitForClients = true;
    bool mdsIsInstalled = false;
	uint32_t keychainAclDefault = CSSM_ACL_KEYCHAIN_PROMPT_INVALID | CSSM_ACL_KEYCHAIN_PROMPT_UNSIGNED;
	unsigned int verbose = 0;
	
	// check for the Installation-DVD environment and modify some default arguments if found
	if (access("/etc/rc.cdrom", F_OK) == 0) {	// /etc/rc.cdrom exists
        secnotice("SecServer", "starting in installmode");
	}

	// parse command line arguments
	extern char *optarg;
	extern int optind;
	int arg;
	while ((arg = getopt(argc, argv, ":dE:im:t:T:uvW")) != -1) {
		switch (arg) {
		case 'd':
			debugMode = true;
			break;
        case 'E':
            /* was entropyFile, kept to preserve ABI */
            break;
		case 'i':
			keychainAclDefault &= ~CSSM_ACL_KEYCHAIN_PROMPT_INVALID;
			break;
        case 'm':
            mdsIsInstalled = true;
            break;
		case 't':
			if ((maxThreads = atoi(optarg)) < 0)
				maxThreads = 0;
			break;
		case 'T':
			if ((workerTimeout = atoi(optarg)) < 0)
				workerTimeout = 0;
			break;
		case 'W':
			waitForClients = false;
			break;
		case 'u':
			keychainAclDefault &= ~CSSM_ACL_KEYCHAIN_PROMPT_UNSIGNED;
			break;
		case 'v':
			verbose++;
			break;
		default:
			usage(argv[0]);
		}
	}
	
	// take no non-option arguments
	if (optind < argc) {
		usage(argv[0]);
	}

	const char *bootstrapName = SECURITYSERVER_BOOTSTRAP_NAME;
	const char* messagingName = SharedMemoryCommon::kDefaultSecurityMessagesName;

	// configure logging first
	if (debugMode) {
		Syslog::open(bootstrapName, LOG_AUTHPRIV, LOG_PERROR);
		Syslog::notice("%s started in debug mode", argv[0]);
	} else {
		Syslog::open(bootstrapName, LOG_AUTHPRIV, LOG_CONS);
	}
    
    // if we're not running as root in production mode, fail
    // in debug mode, issue a warning
    if (uid_t uid = getuid()) {
#if defined(NDEBUG)
        Syslog::alert("Tried to run securityd as user %d: aborted", uid);
        fprintf(stderr, "You are not allowed to run securityd\n");
        exit(1);
#else
        fprintf(stderr, "securityd is unprivileged (uid=%d); some features may not work.\n", uid);
#endif //NDEBUG
    }
    
    // turn into a properly diabolical daemon unless debugMode is on
    if (!debugMode && getppid() != 1 && !Daemon::incarnate(false)) {
		exit(1);	// can't daemonize
	}
        
    // arm signal handlers; code below may generate signals we want to see
    if (signal(SIGCHLD, handleSignals) == SIG_ERR
		|| signal(SIGINT, handleSignals) == SIG_ERR
		|| signal(SIGTERM, handleSignals) == SIG_ERR
		|| signal(SIGPIPE, handleSignals) == SIG_ERR
#if !defined(NDEBUG)
		|| signal(SIGUSR1, handleSignals) == SIG_ERR
#endif //NDEBUG
		|| signal(SIGUSR2, handleSignals) == SIG_ERR) {
		perror("signal");
		exit(1);
	}

// The clang static analyzer isn't a big fan of our "object creation hooks object into global pointer graph" model.
// Tell it not to worry.
    [[clang::suppress]] {
	// introduce all supported ACL subject types
	new AnyAclSubject::Maker();
	new PasswordAclSubject::Maker();
    new ProtectedPasswordAclSubject::Maker();
    new PromptedAclSubject::Maker();
	new ThresholdAclSubject::Maker();
	new CommentAclSubject::Maker();
 	new ProcessAclSubject::Maker();
	new CodeSignatureAclSubject::Maker();
	new KeychainPromptAclSubject::Maker(keychainAclDefault);
	new PartitionAclSubject::Maker();
	new PreAuthorizationAcls::OriginMaker();
    new PreAuthorizationAcls::SourceMaker();
    }
    // establish the code equivalents database
    CodeSignatures codeSignatures;


    // create the main server object and register it
 	Server server(codeSignatures, bootstrapName);

    // Remember the primary service port to send signal events to
    gMainServerPort = server.primaryServicePort();

    // set server configuration from arguments, if specified
	if (workerTimeout)
		server.timeout(workerTimeout);
	if (maxThreads)
		server.maxThreads(maxThreads);
	server.floatingThread(true);
	server.waitForClients(waitForClients);
	server.verbosity(verbose);

    // create the RootSession object (if -d, give it graphics and tty attributes)
    RootSession rootSession(debugMode ? (sessionHasGraphicAccess | sessionHasTTY) : 0, server);
	
	// create a monitor thread to watch for audit session events
	AuditMonitor audits(gMainServerPort);
	audits.threadRun();
    
    // install MDS (if needed) and initialize the local CSSM
    server.loadCssm(mdsIsInstalled);

    // create the shared memory notification hub
    [[clang::suppress]] new SharedMemoryListener(messagingName, kSharedMemoryPoolSize);
	

	// okay, we're ready to roll
    secnotice("SecServer", "Entering service as %s", (char*)bootstrapName);
	Syslog::notice("Entering service");
    
	// go
	server.run();
	
	// fell out of runloop (should not happen)
	Syslog::alert("Aborting");
    return 1;
}


//
// Issue usage message and die
//
static void usage(const char *me)
{
	fprintf(stderr, "Usage: %s [-dwX]"
		"\n\t[-e equivDatabase] 					path to code equivalence database"
		"\n\t[-t maxthreads] [-T threadTimeout]     server thread control"
		"\n", me);
	exit(2);
}

//
// Handle signals.
// We send ourselves a message (through the "self" service), so actual
// actions happen on the normal event loop path. Note that another thread
// may be picking up the message immediately.
//
static void handleSignals(int sig)
{
	(void)self_client_handleSignal(gMainServerPort, sig);
}
