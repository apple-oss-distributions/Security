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


#ifndef _DBQUERY_H_
#define _DBQUERY_H_  1

#include <security_cdsa_utilities/handleobject.h>

#ifdef _CPP_DBQUERY
# pragma export on
#endif

namespace Security
{

class DbQuery: public HandleObject
{
    NOCOPY(DbQuery);
public:
    DbQuery ();
    virtual ~DbQuery ();
};

} // end namespace Security

#ifdef _CPP_DBQUERY
# pragma export off
#endif

#endif // _DBQUERY_H_
