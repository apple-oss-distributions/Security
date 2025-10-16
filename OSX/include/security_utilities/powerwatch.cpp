/*
 * Copyright (c) 2000-2004,2011-2014 Apple Inc. All Rights Reserved.
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
// powerwatch - hook into system notifications of power events
//
#include "powerwatch.h"
#include <IOKit/IOMessage.h>

#if TARGET_OS_OSX

namespace Security {
namespace MachPlusPlus {


//
// The obligatory empty virtual destructor
//
PowerWatcher::~PowerWatcher()
{ }


//
// The default NULL implementations of the callback virtuals.
// We define these (rather than leaving them abstract) since
// many users want only one of these events.
//
void PowerWatcher::systemWillSleep()
{ }

void PowerWatcher::systemIsWaking()
{ }

void PowerWatcher::systemWillPowerDown()
{ }

void PowerWatcher::systemWillPowerOn()
{ }

//
// IOPowerWatchers
//

IOPowerWatcher::IOPowerWatcher() :
    mKernelPort(0)
{
	if (!(mKernelPort = ::IORegisterForSystemPower(this, &mPortRef, ioCallback, &mHandle)))
		UnixError::throwMe(EINVAL);	// no clue
}

IOPowerWatcher::~IOPowerWatcher()
{
	if (mKernelPort)
		::IODeregisterForSystemPower(&mHandle);
}

//
// The callback dispatcher
//
void IOPowerWatcher::ioCallback(void *refCon, io_service_t service,
    natural_t messageType, void *argument)
{
    IOPowerWatcher *me = (IOPowerWatcher *)refCon;
    enum { allow, refuse, ignore } reaction;
    switch (messageType) {
    case kIOMessageSystemWillSleep:
        secnotice("powerwatch", "system will sleep");
        me->systemWillSleep();
        reaction = allow;
        break;
    case kIOMessageSystemHasPoweredOn:
        secnotice("powerwatch", "system has powered on");
        me->systemIsWaking();
        reaction = ignore;
        break;
    case kIOMessageSystemWillPowerOff:
        secnotice("powerwatch", "system will power off");
        me->systemWillPowerDown();
        reaction = allow;
        break;
    case kIOMessageSystemWillNotPowerOff:
        secnotice("powerwatch", "system will not power off");
        reaction = ignore;
        break;
    case kIOMessageCanSystemSleep:
        secnotice("powerwatch", "can system sleep");
        reaction = allow;
        break;
    case kIOMessageSystemWillNotSleep:
        secnotice("powerwatch", "system will not sleep");
        reaction = ignore;
        break;
    case kIOMessageCanSystemPowerOff:
        secnotice("powerwatch", "can system power off");
        reaction = allow;
        break;
	case kIOMessageSystemWillPowerOn:
        secnotice("powerwatch", "system will power on");
		me->systemWillPowerOn();
        reaction = ignore;
        break;
    default:
        secnotice("powerwatch",
            "type 0x%x message received (ignored)", messageType);
        reaction = ignore;
        break;
    }
    
    // handle acknowledgments
    switch (reaction) {
    case allow:
		secnotice("powerwatch", "calling IOAllowPowerChange");
        IOAllowPowerChange(me->mKernelPort, long(argument));
        break;
    case refuse:
		secnotice("powerwatch", "calling IOCancelPowerChange");
        IOCancelPowerChange(me->mKernelPort, long(argument));
        break;
    case ignore:
		secnotice("powerwatch", "sending no response");
        break;
    }
}


//
// The MachServer hookup
//
PortPowerWatcher::PortPowerWatcher()
{
    port(IONotificationPortGetMachPort(mPortRef));
}

boolean_t PortPowerWatcher::handle(mach_msg_header_t *in)
{
    IODispatchCalloutFromMessage(NULL, in, mPortRef);
    return TRUE;
}


} // end namespace MachPlusPlus

} // end namespace Security

#endif //TARGET_OS_OSX
