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

#include "SecPassword.h"
#include "Password.h"

#include "SecBridge.h"

#include "KCExceptions.h"
#include <Security/Authorization.h>
#include <Security/AuthorizationTagsPriv.h>

#include <os/activity.h>

#include "LegacyAPICounts.h"

OSStatus
SecGenericPasswordCreate(SecKeychainAttributeList *searchAttrList, SecKeychainAttributeList *itemAttrList, SecPasswordRef *itemRef)
{
    BEGIN_SECAPI
    os_activity_t activity = os_activity_create("SecGenericPasswordCreate", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_IF_NONE_PRESENT);
    os_activity_scope(activity);
    os_release(activity);
    KCThrowParamErrIf_( (itemRef == NULL) );
    KCThrowParamErrIf_( (searchAttrList == NULL) ^ (itemAttrList == NULL) ); // Both or neither
    
    Password passwordItem(kSecGenericPasswordItemClass, searchAttrList, itemAttrList);
    if (itemRef)
        *itemRef = passwordItem->handle();
    
	END_SECAPI
}

OSStatus
SecPasswordSetInitialAccess(SecPasswordRef itemRef, SecAccessRef accessRef)
{
	BEGIN_SECAPI
    os_activity_t activity = os_activity_create("SecPasswordSetInitialAccess", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_IF_NONE_PRESENT);
    os_activity_scope(activity);
    os_release(activity);
	PasswordImpl::required(itemRef)->setAccess(Access::required(accessRef));
	END_SECAPI
}

OSStatus
SecPasswordAction(SecPasswordRef itemRef, CFTypeRef message, UInt32 flags, UInt32 *length, const void **data)
{
    BEGIN_SECAPI
    os_activity_t activity = os_activity_create("SecPasswordAction", OS_ACTIVITY_CURRENT, OS_ACTIVITY_FLAG_IF_NONE_PRESENT);
    os_activity_scope(activity);
    os_release(activity);

    Password passwordRef = PasswordImpl::required(itemRef);
    
    void *passwordData = NULL;
    UInt32 passwordLength = 0;
	bool gotPassword = false;

    // no flags has no meaning, and there is no apparent default
    assert( flags );
    
    // fail can only be combined with get or new
    assert( (flags & kSecPasswordFail) ? ((flags & kSecPasswordGet) || (flags & kSecPasswordNew)) : true );

    // XXX/cs replace this with our CFString->UTF8 conversion
    const char *messageData = NULL;
    auto_array<char> messageBuffer;
    
    if (message && (CFStringGetTypeID() == CFGetTypeID(message)))
    {
        messageData = CFStringGetCStringPtr(static_cast<CFStringRef>(message), kCFStringEncodingUTF8);

        if (messageData == NULL)
        {
            CFIndex maxLen = CFStringGetMaximumSizeForEncoding(CFStringGetLength(static_cast<CFStringRef>(message)), kCFStringEncodingUTF8) + 1;

            messageBuffer.allocate(maxLen);
            if (CFStringGetCString(static_cast<CFStringRef>(message), messageBuffer.get(), maxLen, kCFStringEncodingUTF8))
                messageData = messageBuffer.get();
        }
    }
    
    if (passwordRef->useKeychain() && !(flags & kSecPasswordNew) && !(flags & kSecPasswordFail))
    {
            // Pull out data and if it's successful return it
            if (flags & kSecPasswordGet)
            {
            
                // XXX/cs if there are unsaved changes this doesn't work
                //        so doing a Get followed by a Get|Set will do the wrong thing
            
                // check mItem whether it's got data
                if (passwordRef->getData(length, data))
                    return errSecSuccess;
            }
            
            // User might cancel here, immediately return that too (it will be thrown)            
    }

    // If we're still here we're not using the keychain or it wasn't there yet
    
    // Do the authorization call to get the password, unless only kSecPasswordSet is specified)
    if ((flags & kSecPasswordNew) || (flags & kSecPasswordGet))
    {
        AuthorizationRef authRef;
        OSStatus status = AuthorizationCreate(NULL,NULL,0,&authRef);
        if (status != errSecSuccess)
        {
            MacOSError::throwMe(status);
        }
        
        AuthorizationItem right = { NULL, 0, NULL, 0 };
        AuthorizationItemSet rightSet = { 1, &right };
        uint32_t reason, tries;
        bool keychain = 0, addToKeychain = 0;

        if (passwordRef->useKeychain())
        {
            keychain = 1;
            addToKeychain = passwordRef->rememberInKeychain();
        }
		else
		{
            keychain = 0;
            addToKeychain = 0;
		}
        
        // Get|Fail conceivable would have it enabled, but since the effect is that it will get overwritten
        // we'll make the user explicitly do it       
        if (flags & kSecPasswordGet)
            addToKeychain = 0; // turn it off for old items that weren't successfully retrieved from the keychain

        if (flags & kSecPasswordFail) // set up retry to reflect failure
        {
	        tries = 1;
            if (flags & kSecPasswordNew)
                reason = 34; // passphraseUnacceptable = 34 passphrase unacceptable for some other reason
            else
                reason = 21; // invalidPassphrase = 21 passphrase was wrong
        }
        else
		{
			reason = 0;
			tries = 0;
		}

        if (flags & kSecPasswordNew) // pick new passphrase
            right.name = "com.apple.builtin.generic-new-passphrase";
        else
            right.name = "com.apple.builtin.generic-unlock";

        bool showPassword = false;
        
        AuthorizationItem envRights[6] = { { AGENT_HINT_RETRY_REASON, sizeof(reason), &reason, 0 },
                                            { AGENT_HINT_TRIES, sizeof(tries), &tries, 0 },
                                            { AGENT_HINT_CUSTOM_PROMPT, messageData ? strlen(messageData) : 0, const_cast<char*>(messageData), 0 },
                                            { AGENT_HINT_ALLOW_SHOW_PASSWORD, showPassword ? strlen("YES") : strlen("NO"), const_cast<char *>(showPassword ? "YES" : "NO"), 0 },
                                            { AGENT_HINT_SHOW_ADD_TO_KEYCHAIN, keychain ? strlen("YES") : strlen("NO"), const_cast<char *>(keychain ? "YES" : "NO"), 0 },
                                            { AGENT_ADD_TO_KEYCHAIN, addToKeychain ? strlen("YES") : strlen("NO"), const_cast<char *>(addToKeychain ? "YES" : "NO"), 0 } };
                                            
        AuthorizationItemSet envSet = { sizeof(envRights) / sizeof(*envRights), envRights };

	    secinfo("SecPassword", "dialog(%s)%s%s%s.", right.name, tries?" retry":"", keychain?" show-add-keychain":"", addToKeychain?" save-to-keychain":"");

        status = AuthorizationCopyRights(authRef, &rightSet, &envSet, kAuthorizationFlagDefaults|kAuthorizationFlagInteractionAllowed|kAuthorizationFlagExtendRights, NULL);
        
        if (status)
        {
            AuthorizationFree(authRef, 0);
            return status;
        }
        
        // if success pull the data
        AuthorizationItemSet *returnedInfo;
        status = AuthorizationCopyInfo(authRef, NULL, &returnedInfo);
        
        if (status)
        {
            AuthorizationFree(authRef, 0);
            
            return status;
        }
        
        if (returnedInfo && (returnedInfo->count > 0))
        {
            for (uint32_t index = 0; index < returnedInfo->count; index++)
            {
                AuthorizationItem &item = returnedInfo->items[index];
                
                if (!strcmp(AGENT_PASSWORD, item.name))
                {
					gotPassword = true;
                    passwordLength = (UInt32)item.valueLength;

                    if (passwordLength)
                    {
                        Allocator &allocator = Allocator::standard();
                        passwordData = allocator.malloc(passwordLength);
                        if (passwordData)
                            memcpy(passwordData, item.value, passwordLength);
                    }
                    
                    if (length)
                        *length = passwordLength;
                    if (data) 
                        *data = passwordData;
						
					secinfo("SecPassword", "Got password (%u,%p).", (unsigned int)passwordLength, passwordData);
                }
                else if (!strcmp(AGENT_ADD_TO_KEYCHAIN, item.name))
                {
                    bool remember = (item.value && item.valueLength == strlen("YES") && !memcmp("YES", static_cast<char *>(item.value), item.valueLength));
					passwordRef->setRememberInKeychain(remember);
					if (remember)
						secinfo("SecPassword", "User wants to add the password to the Keychain.");
                }
            }
        }

        if(returnedInfo) {
            AuthorizationFreeItemSet(returnedInfo);
        }
        AuthorizationFree(authRef, 0);
        
    }

    // If we're still here the user gave us their password, store it if keychain is in use
    if (passwordRef->useKeychain())
    {
        if (passwordRef->rememberInKeychain()) {
            if (gotPassword)
				passwordRef->setData(passwordLength, passwordData);
			if (flags & kSecPasswordSet)
            {
				passwordRef->save();
                gotPassword = true;
            }
		}
    }

    if (!gotPassword)
    {
        return errAuthorizationDenied;
    }
    
    END_SECAPI
}
