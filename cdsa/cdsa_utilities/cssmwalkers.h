/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All Rights Reserved.
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
// cssmwalkers - walkers for standard CSSM datatypes and wrappers
//
#ifndef _H_CSSMWALKERS
#define _H_CSSMWALKERS

#include <Security/walkers.h>

#ifdef _CPP_CSSMWALKERS
# pragma export on
#endif


namespace Security
{

namespace DataWalkers
{

//
// Walk an INLINE CSSM_DATA by dealing with the data it points to.
// Note that this is not the walker for an OUT OF LINE CSSM_DATA,
// which is quite regular and handled below.
//
template <class Action>
void walk(Action &operate, CSSM_DATA &data)
{
	void *p = data.Data;
	operate(p, data.Length);
	data.Data = reinterpret_cast<unsigned char *>(p);
}


//
// Walking a C string is almost regular (the size comes from strlen()).
//
template <class Action>
char *walk(Action &operate, char * &s)
{
    // A string's length is obtained by reading the string value.
    // We must honor the operator's preference for not calculating length
    // (e.g. because s won't be valid until some magic thing was done to it).
	operate(s, operate.needsSize ? (strlen(s) + 1) : 0);
	return s;
}


//
// We "walk" an integer by simply returning it unchanged.
// This is a degenerate special case that makes some templated
// uses of walking easier (notably for Context use). Note that
// the action is never called, so operations don't need to be able
// to cope with integer (non-ref) arguments. This is strictly for
// notational convenience.
//
template <class Action>
uint32 walk(Action &, uint32 arg)
{
	return arg;
}


//
// Flattener functions for common CSSM data types that have internal
// structure. (The flat ones are handled by the default above.)
//
template <class Action>
CssmData *walk(Action &operate, CssmData * &data)
{
	operate(data);
	walk(operate, *data);
	return data;
}

template <class Action>
CSSM_DATA *walk(Action &operate, CSSM_DATA * &data)
{ return walk(operate, CssmData::overlayVar(data)); }

template <class Action>
CssmKey *walk(Action &operate, CssmKey * &key)
{
	operate(key);
	walk(operate, static_cast<CssmData &>(*key));
	return key;
}

template <class Action>
CSSM_KEY *walk(Action &operate, CSSM_KEY * &data)
{ return walk(operate, CssmKey::overlayVar(data)); }

template <class Action>
CssmCryptoData *walk(Action &operate, CssmCryptoData * &data)
{
	operate(data);
	walk(operate, data->param());
	return data;
}

template <class Action>
CSSM_CRYPTO_DATA *walk(Action &operate, CSSM_CRYPTO_DATA * &data)
{ return walk(operate, CssmCryptoData::overlayVar(data)); }

template <class Action>
CSSM_PKCS5_PBKDF2_PARAMS *walk(Action &operate, CSSM_PKCS5_PBKDF2_PARAMS * &data)
{
    operate(data);
    walk(operate, data->Passphrase);
    return data;
}


} // end namespace DataWalkers

} // end namespace Security

#ifdef _CPP_CSSMWALKERS
# pragma export off
#endif

#endif //_H_CSSMWALKERS
