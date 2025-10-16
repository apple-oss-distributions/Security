/*
 * Copyright (c) 2011,2014 Apple Inc. All Rights Reserved.
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

#ifndef __SHARED_MEMORY_COMMON__
#define __SHARED_MEMORY_COMMON__



#include <sys/types.h>

const unsigned kSegmentSize = 4096;
const unsigned kNumberOfSegments = 8;
const unsigned kSharedMemoryPoolSize = kSegmentSize * kNumberOfSegments;

const unsigned kBytesWrittenOffset = 0;
const unsigned kBytesWrittenLength = 4;
const unsigned kPoolAvailableForData = kSharedMemoryPoolSize - kBytesWrittenLength;

typedef u_int32_t SegmentOffsetType;

class SharedMemoryCommon
{
public:
    SharedMemoryCommon() {}
    virtual ~SharedMemoryCommon ();

    // Is this a system user or a regular user?
    static uid_t fixUID(uid_t uid) { return (uid < 500) ? 0 : uid; }

    static std::string SharedMemoryFilePath(const char *segmentName, uid_t uid);
    static std::string notificationDescription(int domain, int event);

    constexpr static const char* const kMDSDirectory = "/private/var/db/mds/";
    constexpr static const char* const kMDSMessagesDirectory = "/private/var/db/mds/messages/";
    constexpr static const char* const kUserPrefix = "se_";

    constexpr static const char* const kDefaultSecurityMessagesName = "SecurityMessages";
};


#endif
