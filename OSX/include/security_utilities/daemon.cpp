/*
 * Copyright (c) 2000-2004,2011,2014 Apple Inc. All Rights Reserved.
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
// demon - support code for writing UNIXoid demons
//
#include <security_utilities/daemon.h>
#include <security_utilities/logging.h>
#include <security_utilities/debugging.h>
#include <sys/types.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

namespace Security {
namespace Daemon {

//
// Daemonize this process, the UNIX way.
//
bool incarnate(bool doFork /*=true*/)
{
	if (doFork) {
		// fork with slight resilience
		for (int forkTries = 1; forkTries <= 5; forkTries++) {
			switch (fork()) {
				case 0:			// child
							// we are the daemon process (Har! Har!)
					break;
				case -1:		// parent: fork failed
					switch (errno) {
						case EAGAIN:
						case ENOMEM:
							Syslog::warning("fork() short on resources (errno=%d); retrying", errno);
							sleep(forkTries);
							continue;
						default:
							Syslog::error("fork() failed (errno=%d)", errno);
							return false;
					}
				default:		// parent
							// @@@ we could close an assurance loop here, but we don't (yet?)
					exit(0);
			}
		}
		// fork succeeded; we are the child; parent is terminating
	}
	
	// create new session (the magic set-me-apart system call)
	setsid();

	// redirect standard channels to /dev/null
	close(0);	// fail silently in case 0 is closed
	if (open("/dev/null", O_RDWR, 0) == 0) {	// /dev/null could be missing, I suppose...
		dup2(0, 1);
		dup2(0, 2);
	}
	
	// ready to roll
	return true;
}

} // end namespace Daemon
} // end namespace Security
