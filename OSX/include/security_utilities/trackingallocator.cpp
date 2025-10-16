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
// cssmalloc - memory allocation in the CDSA world.
//
// Don't eat heavily before inspecting this code.
//
#include <security_utilities/trackingallocator.h>


//
// The default action of the destructor is to free all memory.
//
TrackingAllocator::~TrackingAllocator()
{
	reset();
}


//
// Standard allocation operations.
// We pass them down to our subAllocator and keep track of what we've got.
//
void *TrackingAllocator::malloc(size_t inSize)
{
	void *anAddress = subAllocator.malloc(inSize);
	mAllocSet.insert(anAddress);
	return anAddress;
}

void TrackingAllocator::free(void *inAddress) _NOEXCEPT
{
	subAllocator.free(inAddress);
	mAllocSet.erase(inAddress);
}

void *TrackingAllocator::realloc(void *inAddress, size_t inNewSize)
{
	void *anAddress = subAllocator.realloc(inAddress, inNewSize);
	if (anAddress != inAddress)
	{
		mAllocSet.erase(inAddress);
		mAllocSet.insert(anAddress);
	}

	return anAddress;
}


//
// Free all memory allocated through this Allocator (since the last commit(), if any)
//
void TrackingAllocator::reset()
{
	AllocSet::iterator first = mAllocSet.begin(), last = mAllocSet.end();
	for (; first != last; ++first)
		subAllocator.free(*first);
}


//
// Forget about all allocated memory. It's now your responsibility.
//
void TrackingAllocator::commit()
{
	mAllocSet.clear();
}
