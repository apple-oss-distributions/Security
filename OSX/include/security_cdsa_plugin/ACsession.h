/*
 * Copyright (c) 2000-2001,2011,2014 Apple Inc. All Rights Reserved.
 * 
 * The contents of this file constitute Original Code as defined in and are
 * subject to the Apple Public Source License Version 1.2 (the 'License').
 * You may not use this file except in compliance with the License. Please obtain
 * a copy of the License at http://www.apple.com/publicsource and read it before
 * using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESS
 * OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES, INCLUDING WITHOUT
 * LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
 * PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. Please see the License for the
 * specific language governing rights and limitations under the License.
 */


//
// ACsession.h - Framework for AC plugin modules
//
#ifndef _H_ACSESSION
#define _H_ACSESSION

#include <security_cdsa_plugin/ACabstractsession.h>

namespace Security
{

//
// The abstract ACPluginSession class is the common ancestor of your implementation
// object for an AC type plugin attachment session. Inherit from this and implement
// the abstract methods to define a plugin session.
//
class ACPluginSession : public PluginSession, public ACAbstractPluginSession {
public:
    ACPluginSession(CSSM_MODULE_HANDLE theHandle,
                    CssmPlugin &plug,
                    const CSSM_VERSION &version,
                    uint32 subserviceId,
                    CSSM_SERVICE_TYPE subserviceType,
                    CSSM_ATTACH_FLAGS attachFlags,
                    const CSSM_UPCALLS &upcalls)
      : PluginSession(theHandle, plug, version, subserviceId, subserviceType, attachFlags, upcalls) { }

protected:
    CSSM_MODULE_FUNCS_PTR construct();
};

} // end namespace Security

#endif //_H_ACSESSION
