/*
 * Copyright (c) 2003-2004,2006-2010,2013-2014 Apple Inc. All Rights Reserved.
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
 *
 * readline.h
 */

#ifndef _READLINE_H_
#define _READLINE_H_  1

#include <CoreFoundation/CFData.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Inspects a file's existence. Returns a file handle or -1 on failure. Does not check file size */
int inspect_file(const char* name, off_t *out_off_end);

/* Read a line from stdin into buffer as a null terminated string.  If buffer is
   non NULL use at most buffer_size bytes and return a pointer to buffer.  Otherwise
   return a newly malloced buffer.
   if EOF is read this function returns NULL.  */
extern char *readline(char *buffer, int buffer_size);

extern CFDataRef copyFileContents(const char *path);

extern bool writeFileContents(const char *path, CFDataRef data);

#ifdef __cplusplus
}
#endif

#endif /* _READLINE_H_ */
