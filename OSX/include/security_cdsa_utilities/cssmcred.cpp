/*
 * Copyright (c) 2000-2001,2003-2004,2006,2011,2014 Apple Inc. All Rights Reserved.
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
// cssmcred - enhanced PodWrappers and construction aids for ACL credentials
//
#include <security_cdsa_utilities/cssmcred.h>


namespace Security {

//
// Scan a SampleGroup for samples with a given CSSM_SAMPLE_TYPE.
// Collect all matching samples into a list (which is cleared to begin with).
// Return true if any were found, false if none.
// Throw if any of the samples are obviously malformed.
//
bool SampleGroup::collect(CSSM_SAMPLE_TYPE sampleType, list<CssmSample> &matches) const
{
	for (uint32 n = 0; n < length(); n++) {
		TypedList sample = (*this)[n];
		sample.checkProper();
		if (sample.type() == sampleType) {
			sample.snip();	// skip sample type
			matches.push_back(sample);
		}
	}
	return !matches.empty();
}


//
// AccessCredentials
//
const AccessCredentials& AccessCredentials::null_credential()
{
    static const CSSM_ACCESS_CREDENTIALS null_credentials = { "" };    // and more nulls
    return AccessCredentials::overlay(null_credentials);
}

void AccessCredentials::tag(const char *tagString)
{
	if (tagString == NULL)
		EntryTag[0] = '\0';
	else if (strlen(tagString) > CSSM_MODULE_STRING_SIZE)
		CssmError::throwMe(CSSM_ERRCODE_INVALID_ACL_ENTRY_TAG);
	else
		strcpy(EntryTag, tagString);
}

bool AccessCredentials::authorizesUI() const {
    list<CssmSample> uisamples;

    if(samples().collect(CSSM_SAMPLE_TYPE_KEYCHAIN_PROMPT, uisamples)) {
        // The existence of a lone keychain prompt gives UI access
        return true;
    }

    samples().collect(CSSM_SAMPLE_TYPE_KEYCHAIN_LOCK, uisamples);
    samples().collect(CSSM_SAMPLE_TYPE_THRESHOLD, uisamples);

    for (list<CssmSample>::iterator it = uisamples.begin(); it != uisamples.end(); it++) {
        TypedList &sample = *it;

        if(!sample.isProper()) {
            secnotice("integrity", "found a non-proper sample, skipping...");
            continue;
        }

        switch (sample.type()) {
            case CSSM_SAMPLE_TYPE_KEYCHAIN_PROMPT:
                // these credentials allow UI
                return true;
        }
    }

    // no interesting credential found; no UI for you
    return false;
}

//
// AutoCredentials self-constructing credentials structure
//
AutoCredentials::AutoCredentials(Allocator &alloc) : allocator(alloc)
{
	init();
}

AutoCredentials::AutoCredentials(Allocator &alloc, uint32 nSamples) : allocator(alloc)
{
	init();
	getSample(nSamples - 1);	// extend array to nSamples elements
}

void AutoCredentials::init()
{
	sampleArray = NULL;
	nSamples = 0;
}


CssmSample &AutoCredentials::getSample(uint32 n)
{
	if (n >= nSamples) {
		sampleArray = allocator.alloc<CssmSample>(sampleArray, nSamples = n + 1);
		Samples.Samples = sampleArray;
		Samples.NumberOfSamples = nSamples;
	}
	return sampleArray[n];
}

}	// end namespace Security
