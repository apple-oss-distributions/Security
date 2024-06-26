#ifndef __SECEXTERNALSOURCETRANSFORM_H__
#define __SECEXTERNALSOURCETRANSFORM_H__

/*
 * Copyright (c) 2010-2011 Apple Inc. All Rights Reserved.
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

#include <Security/SecTransform.h>

#ifdef __cplusplus
extern "C" {
#endif
	
	/*!
	 @function SecExternalSourceTransformCreate
	 @abstract			Creates an encode computation object.
	 @param error		A pointer to a CFErrorRef.  This pointer will be set
	 if an error occurred.  This value may be NULL if you
	 do not want an error returned.
	 @result				A pointer to a SecTransformRef object.  This object must
	 be released with CFRelease when you are done with
	 it.  This function will return NULL if an error
	 occurred.
	 @discussion			This function creates a transform which forwards external values
	 */
	
	
	SecTransformRef SecExternalSourceTransformCreate(CFErrorRef* error
											 )
    API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst);
	
	
	Boolean SecExternalSourceSetValue(SecTransformRef externalSourceTransform,
									  CFTypeRef value,
									  CFErrorRef *error
									  )
    API_DEPRECATED("SecTransform is no longer supported", macos(10.7, 13.0)) API_UNAVAILABLE(ios, tvos, watchos, macCatalyst);

	
	
#ifdef __cplusplus
}
#endif


#endif
