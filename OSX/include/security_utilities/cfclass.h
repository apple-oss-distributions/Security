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

#ifndef _CFCLASS_H
#define _CFCLASS_H

#include <list>
#include <CoreFoundation/CFRuntime.h>
#include "threading.h"

namespace Security {

//
// CFClass
//
class CFClass : protected CFRuntimeClass
{
public:
    explicit CFClass(const char *name);

	CFTypeID typeID;

private:
	static void finalizeType(CFTypeRef cf) _NOEXCEPT;
    static Boolean equalType(CFTypeRef cf1, CFTypeRef cf2) _NOEXCEPT;
    static CFHashCode hashType(CFTypeRef cf) _NOEXCEPT;
	static CFStringRef copyFormattingDescType(CFTypeRef cf, CFDictionaryRef dict) _NOEXCEPT;
	static CFStringRef copyDebugDescType(CFTypeRef cf) _NOEXCEPT;
    static uint32_t refCountForType(intptr_t op, CFTypeRef cf) _NOEXCEPT;
    static uint32_t cleanupObject(intptr_t op, CFTypeRef cf, bool &zap);
};

} // end namespace Security

#endif
