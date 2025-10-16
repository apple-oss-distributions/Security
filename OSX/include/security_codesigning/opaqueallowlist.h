/*
 * Copyright (c) 2014 Apple Inc. All Rights Reserved.
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
#ifndef _H_OPAQUEALLOWLIST
#define _H_OPAQUEALLOWLIST

#include "SecAssessment.h"
#include <Security/CodeSigning.h>
#include <security_utilities/sqlite++.h>
#include <dispatch/dispatch.h>

namespace Security {
namespace CodeSigning {


namespace SQLite = SQLite3;


static const char opaqueDatabase[] = "/private/var/db/gkopaque.bundle/Contents/Resources/gkopaque.db";


class OpaqueAllowlist : public SQLite::Database {
public:
	OpaqueAllowlist(const char *path = NULL, int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOFOLLOW);
	virtual ~OpaqueAllowlist();

public:
	void add(SecStaticCodeRef code);
	bool contains(SecStaticCodeRef code, SecAssessmentFeedback feedback, OSStatus reason);
	
	CFDictionaryRef validationConditionsFor(SecStaticCodeRef code);

private:
	dispatch_queue_t mOverrideQueue;
};


} // end namespace CodeSigning
} // end namespace Security

#endif //_H_OPAQUEALLOWLIST
