/*
 * Copyright (c) 2003-2007,2009-2010,2013-2014 Apple Inc. All Rights Reserved.
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
 * keychain_find.c
 */

#include <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>

#include <Security/SecItem.h>
#include <Security/SecItemPriv.h>

#include "SecurityTool/sharedTool/tool_errors.h"
#include "SecurityTool/sharedTool/readline.h"

#include <utilities/SecCFWrappers.h>

#include "SecurityCommands.h"

#include "keychain_util.h"
#include <Security/SecAccessControl.h>
#include <Security/SecAccessControlPriv.h>

#import <SecurityFoundation/SFKeychain.h>

#include "tool_auth_helpers.h"

//
// Craptastic hacks.
#ifndef _SECURITY_SECKEYCHAIN_H_
typedef uint32_t SecProtocolType;
typedef uint32_t SecAuthenticationType;
#endif


static CFMutableDictionaryRef
keychain_create_query_from_string(const char *query) {
    CFMutableDictionaryRef q;

    q = CFDictionaryCreateMutable(0, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (!keychain_query_parse_cstring(q, query)) {
        CFReleaseNull(q);
    }
    return q;
}

static void add_key(const void *key, const void *value, void *context) {
    CFArrayAppendValue(context, key);
}

static void print_error(int error) {
    if (error == errSecItemNotFound) {
        fprintf(stderr, "The specified item could not be found in the keychain.\n");
    } else if (error == errSecInteractionNotAllowed) {
        fprintf(stderr, "User interaction is not allowed. Device may be locked.\n");
    }
}

static bool isPrintableString(CFStringRef theString){
    bool result = false;
    CFCharacterSetRef controlSet = CFCharacterSetGetPredefined(kCFCharacterSetControl);
    CFCharacterSetRef newlineSet = CFCharacterSetGetPredefined(kCFCharacterSetNewline);
    CFCharacterSetRef illegalSet = CFCharacterSetGetPredefined(kCFCharacterSetIllegal);

    CFMutableCharacterSetRef unacceptable = CFCharacterSetCreateMutableCopy(kCFAllocatorDefault, controlSet);
    CFCharacterSetUnion(unacceptable, newlineSet);
    CFCharacterSetUnion(unacceptable, illegalSet);
    result = CFStringFindCharacterFromSet(theString, unacceptable, CFRangeMake(0, CFStringGetLength(theString)), 0, NULL);
    CFReleaseNull(unacceptable);
    return !result;
}

static void display_item(const void *v_item, void *context) {
    CFDictionaryRef item = (CFDictionaryRef)v_item;
    CFIndex dict_count, key_ix, key_count;
    CFMutableArrayRef keys = NULL;
    CFIndex maxWidth = 10; /* Maybe precompute this or grab from context? */

    dict_count = CFDictionaryGetCount(item);
    keys = CFArrayCreateMutable(kCFAllocatorDefault, dict_count,
        &kCFTypeArrayCallBacks);
    CFDictionaryApplyFunction(item, add_key, keys);
    key_count = CFArrayGetCount(keys);
    CFArraySortValues(keys, CFRangeMake(0, key_count),
        (CFComparatorFunction)CFStringCompare, 0);

    for (key_ix = 0; key_ix < key_count; ++key_ix) {
        CFStringRef key = (CFStringRef)CFArrayGetValueAtIndex(keys, key_ix);
        CFTypeRef value = CFDictionaryGetValue(item, key);
        CFMutableStringRef line = CFStringCreateMutable(NULL, 0);

        CFStringAppend(line, key);
        CFIndex jx;
        for (jx = CFStringGetLength(key);
            jx < maxWidth; ++jx) {
            CFStringAppend(line, CFSTR(" "));
        }
        CFStringAppend(line, CFSTR(" : "));
        if (CFStringGetTypeID() == CFGetTypeID(value)) {
            CFStringAppend(line, (CFStringRef)value);
        } else if (CFNumberGetTypeID() == CFGetTypeID(value)) {
            CFNumberRef v_n = (CFNumberRef)value;
            CFStringAppendFormat(line, NULL, CFSTR("%@"), v_n);
        } else if (CFDateGetTypeID() == CFGetTypeID(value)) {
            CFDateRef v_d = (CFDateRef)value;
            CFStringAppendFormat(line, NULL, CFSTR("%@"), v_d);
        } else if (CFGetTypeID(key) == CFStringGetTypeID() && CFStringCompare(key, kSecValuePersistentRef, 0) == 0) {
            NSData* v_d = (__bridge NSData*)(CFDataRef)value;
            NSString* b64 = [v_d base64EncodedStringWithOptions:0];
            CFStringAppendFormat(line, NULL, CFSTR("%@"), (__bridge CFStringRef)b64);
        } else if (CFDataGetTypeID() == CFGetTypeID(value)) {
            CFDataRef v_d = (CFDataRef)value;
            CFStringRef v_s = CFStringCreateFromExternalRepresentation(
                kCFAllocatorDefault, v_d, kCFStringEncodingUTF8);

            if (v_s) {
                if(!isPrintableString(v_s))
                    CFStringAppend(line, CFSTR("not printable "));
                else{
                    CFStringAppend(line, CFSTR("/"));
                    CFStringAppend(line, v_s);
                    CFStringAppend(line, CFSTR("/ "));
                }
            }
            CFReleaseNull(v_s);

            const uint8_t *bytes = CFDataGetBytePtr(v_d);
            CFIndex len = CFDataGetLength(v_d);
            for (jx = 0; jx < len; ++jx) {
                CFStringAppendFormat(line, NULL, CFSTR("%.02X"), bytes[jx]);
            }
        } else if (SecAccessControlGetTypeID() == CFGetTypeID(value)) {
            display_sac_line((SecAccessControlRef)value, line);
        } else {
            CFStringAppendFormat(line, NULL, CFSTR("%@"), value);
        }

        CFStringWriteToFileWithNewline(line, stdout);

		CFRelease(line);
    }
    CFRelease(keys);
    
    CFStringWriteToFileWithNewline(CFSTR("===="), stdout);

    //CFShow(item);
}


static void display_results(CFTypeRef results) {
    if (results && CFGetTypeID(results) == CFArrayGetTypeID()) {
        CFArrayRef r_a = (CFArrayRef)results;
        CFArrayApplyFunction(r_a, CFRangeMake(0, CFArrayGetCount(r_a)),
            display_item, NULL);
    } else if (results && CFGetTypeID(results) == CFDictionaryGetTypeID()) {
        display_item(results, NULL);
    } else {
        fprintf(stderr, "SecItemCopyMatching returned unexpected results:");
        CFShow(results);
    }
}

static NSDictionary* cleanNSDictionaryForJSON(NSDictionary* dict) {
    if(!dict) {
        return nil;
    }
    NSMutableDictionary* mutDict = [NSMutableDictionary dictionary];
    for(id key in dict.allKeys) {
        id obj = dict[key];

        if([obj isKindOfClass:[NSDictionary class]]) {
            mutDict[key] = cleanNSDictionaryForJSON(obj);

        } else if([NSJSONSerialization isValidJSONObject:obj]) {
            mutDict[key] = obj;

        } else if([obj isKindOfClass:[NSString class]]) {
            mutDict[key] = obj;

        } else if([obj isKindOfClass:[NSNumber class]]) {
            mutDict[key] = obj;

        } else if([obj isKindOfClass:[NSData class]]) {
            mutDict[key] = [(NSData*)obj base64EncodedStringWithOptions:0];

        } else if([obj isKindOfClass:[NSDate class]]) {
            NSISO8601DateFormatter* dateFormat = [[NSISO8601DateFormatter alloc] init];
            mutDict[key] = [dateFormat stringFromDate:obj];

        } else if (SecAccessControlGetTypeID() == CFGetTypeID((__bridge CFTypeRef)obj)) {
            NSMutableString* str = [NSMutableString string];
            display_sac_line((__bridge SecAccessControlRef)obj, (__bridge CFMutableStringRef)str);
            mutDict[key] = str;

        } else {
            NSLog(@"can't jsonify: %@ %@ %@", key, obj, [obj class]);
        }
    }
    return mutDict;
}

static void display_results_json(CFTypeRef cfitem) {
    id item = (__bridge id)cfitem;

    if([item isKindOfClass:[NSArray class]]) {
        NSArray* array = (NSArray*)item;
        NSMutableArray* cleanArray = [NSMutableArray array];

        for(id x in array) {
            NSDictionary* cleanDictionary = cleanNSDictionaryForJSON((NSDictionary*)x);
            [cleanArray addObject:cleanDictionary];

            if(![NSJSONSerialization isValidJSONObject:cleanDictionary]) {
                fprintf(stderr, "%s", [[NSString stringWithFormat:@"Can't JSONify: %@", x] UTF8String]);
            }
        }

        NSError* error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:cleanArray
                                                       options:(NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys)
                                                         error:&error];
        if (!json) {
            fprintf(stderr, "%s", [[NSString stringWithFormat:@"error: %@", error.localizedDescription] UTF8String]);
        } else {
            printf("%s\n", [[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] UTF8String]);
        }

    } else if([item isKindOfClass:[NSDictionary class]]) {
        NSError* error = nil;
        NSData *json = [NSJSONSerialization dataWithJSONObject:cleanNSDictionaryForJSON(item)
                                                       options:(NSJSONWritingPrettyPrinted | NSJSONWritingSortedKeys)
                                                         error:&error];
        if (!json) {
            fprintf(stderr, "%s", [[NSString stringWithFormat:@"error: %@", error.localizedDescription] UTF8String]);
        } else {
            printf("%s\n", [[[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding] UTF8String]);
        }

    } else {
        fprintf(stderr, "SecItemCopyMatching returned unexpected results (can't JSONify):");
        CFShow(cfitem);
    }

}

static OSStatus do_find_or_delete(CFDictionaryRef query, bool do_delete) {
    OSStatus result;
    if (do_delete) {
        result = SecItemDelete(query);
        if (result) {
            sec_perror("SecItemDelete", result);
        }
    } else {
        CFTypeRef results = NULL;
        result = SecItemCopyMatching(query, &results);
        if (result) {
            sec_perror("SecItemCopyMatching", result);
        } else {
            display_results(results);
        }
        CFReleaseSafe(results);
    }
    return result;
}

static int
do_keychain_find_or_delete_internet_password(Boolean do_delete,
	const char *serverName, const char *securityDomain,
	const char *accountName, const char *path, UInt16 port,
	SecProtocolType protocol, SecAuthenticationType authenticationType,
	Boolean get_password)
 {
	OSStatus result;
    CFDictionaryRef query = NULL;
    const void *keys[11], *values[11];
    CFIndex ix = 0;

    if (do_delete && !serverName && !securityDomain && !accountName && !path && !port && !protocol && !authenticationType) {
        return SHOW_USAGE_MESSAGE;
    }

    keys[ix] = kSecClass;
    values[ix++] = kSecClassInternetPassword;
	if (serverName) {
		keys[ix] = kSecAttrServer;
		values[ix++] = CFStringCreateWithCStringNoCopy(NULL, serverName,
			kCFStringEncodingUTF8, kCFAllocatorNull);
	}
	if (securityDomain) {
		keys[ix] = kSecAttrSecurityDomain;
		values[ix++] = CFStringCreateWithCStringNoCopy(NULL, securityDomain,
			kCFStringEncodingUTF8, kCFAllocatorNull);
	}
	if (accountName) {
		keys[ix] = kSecAttrAccount;
		values[ix++] = CFStringCreateWithCStringNoCopy(NULL, accountName,
			kCFStringEncodingUTF8, kCFAllocatorNull);
	}
	if (path) {
		keys[ix] = kSecAttrPath;
		values[ix++] = CFStringCreateWithCStringNoCopy(NULL, path,
			kCFStringEncodingUTF8, kCFAllocatorNull);
	}
	if (port != 0) {
		keys[ix] = kSecAttrPort;
		values[ix++] = CFNumberCreate(NULL, kCFNumberSInt16Type, &port);
	}
	if (protocol != 0) {
		/* Protocol is a 4 char code, perhaps we should use a string rep
		   instead. */
		keys[ix] = kSecAttrProtocol;
		values[ix++] = CFNumberCreate(NULL, kCFNumberSInt32Type, &protocol);
	}
	if (authenticationType != 0) {
		keys[ix] = kSecAttrAuthenticationType;
		values[ix++] = CFNumberCreate(NULL, kCFNumberSInt32Type,
			&authenticationType);
	}
    if (get_password) {
        /* Only ask for the data if so required. */
		keys[ix] = kSecReturnData;
		values[ix++] = kCFBooleanTrue;
    }
    keys[ix] = kSecReturnAttributes;
    values[ix++] = kCFBooleanTrue;
	if (!do_delete) {
		/* If we aren't deleting ask for all items. */
		keys[ix] = kSecMatchLimit;
		values[ix++] = kSecMatchLimitAll;
	}

    query = CFDictionaryCreate(NULL, keys, values, ix,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    result = do_find_or_delete(query, do_delete);
    CFReleaseSafe(query);

	return result;
}

static int
parse_fourcharcode(const char *name, uint32_t *code)
{
	/* @@@ Check for errors. */
	char *p = (char *)code;
	strncpy(p, name, 4);
	return 0;
}

static int
keychain_find_or_delete_internet_password(Boolean do_delete, int argc, char * const *argv)
{
	char *serverName = NULL, *securityDomain = NULL, *accountName = NULL, *path = NULL;
    UInt16 port = 0;
    SecProtocolType protocol = 0;
    SecAuthenticationType authenticationType = 0;
	int ch, result = 0;
	Boolean get_password = FALSE;
	bool authSucceeded = false;

	while ((ch = getopt(argc, argv, "a:d:hgp:P:r:s:t:yY:")) != -1)
	{
		switch  (ch)
		{
        case 'a':
            accountName = optarg;
            break;
        case 'd':
            securityDomain = optarg;
			break;
		case 'g':
            if (do_delete)
                return SHOW_USAGE_MESSAGE;
			get_password = TRUE;
			break;
        case 'p':
            path = optarg;
            break;
        case 'P':
            port = atoi(optarg);
            break;
        case 'r':
			result = parse_fourcharcode(optarg, &protocol);
			if (result)
				return result;
			break;
		case 's':
			serverName = optarg;
			break;
        case 't':
			result = parse_fourcharcode(optarg, &authenticationType);
			if (result)
				return result;
			break;
        case 'y':
			if (!promptForAndCheckPassphrase()) {
				return 1;
			}
			authSucceeded = true;
			break;
        case 'Y':
			if (!checkPassphrase(optarg, 0) ) {
				return 1;
			}
			authSucceeded = true;
			break;
        case '?':
		default:
			return SHOW_USAGE_MESSAGE;
		}
	}

	if (!authSucceeded && authRequired()) {
		return 1;
	}

	result = do_keychain_find_or_delete_internet_password(do_delete, serverName, securityDomain,
		accountName, path, port, protocol,authenticationType, get_password);

	return result;
}

int
keychain_find_internet_password(int argc, char * const *argv) {
    return keychain_find_or_delete_internet_password(0, argc, argv);
}

int
keychain_delete_internet_password(int argc, char * const *argv) {
    return keychain_find_or_delete_internet_password(1, argc, argv);
}

static int
do_keychain_find_or_delete_generic_password(Boolean do_delete,
	const char *serviceName, const char *accountName,
	Boolean get_password)
 {
	OSStatus result;
    CFDictionaryRef query = NULL;
    const void *keys[6], *values[6];
    CFIndex ix = 0;

    if (do_delete && !serviceName && !accountName) {
        return SHOW_USAGE_MESSAGE;
    }

    keys[ix] = kSecClass;
    values[ix++] = kSecClassGenericPassword;
	if (serviceName) {
		keys[ix] = kSecAttrService;
		values[ix++] = CFStringCreateWithCStringNoCopy(NULL, serviceName,
			kCFStringEncodingUTF8, kCFAllocatorNull);
	}
	if (accountName) {
		keys[ix] = kSecAttrAccount;
		values[ix++] = CFStringCreateWithCStringNoCopy(NULL, accountName,
			kCFStringEncodingUTF8, kCFAllocatorNull);
	}
    if (get_password) {
        /* Only ask for the data if so required. */
		keys[ix] = kSecReturnData;
		values[ix++] = kCFBooleanTrue;
    }
    keys[ix] = kSecReturnAttributes;
    values[ix++] = kCFBooleanTrue;
	if (!do_delete) {
		/* If we aren't deleting ask for all items. */
		keys[ix] = kSecMatchLimit;
		values[ix++] = kSecMatchLimitAll;
	}

    query = CFDictionaryCreate(NULL, keys, values, ix,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    result = do_find_or_delete(query, do_delete);

	CFReleaseSafe(query);

	return result;
}

int keychain_item(int argc, char * const *argv) {
    int ch = 0;
    __block int result = 0;
    CFMutableDictionaryRef query, update = NULL;
	bool get_password = false;
    bool get_persistent_reference = false;
    bool do_delete = false;
    bool do_add = false;
    bool verbose = false;
    bool json = false;
    int limit = 0;
    bool authSucceeded = false;
    NSString *sharingGroup;

    query = CFDictionaryCreateMutable(0, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
#if TARGET_OS_OSX
    CFDictionarySetValue(query, kSecUseDataProtectionKeychain, kCFBooleanTrue);
#endif

	while ((ch = getopt(argc, argv, "ad:Df:jgpP:q:u:vl:s:yY:")) != -1)
	{
		switch  (ch)
		{
            case 'a':
                do_add = true;
                break;
            case 'D':
                do_delete = true;
                break;
            case 'd':
            {
                CFStringRef dataString = CFStringCreateWithCString(0, optarg, kCFStringEncodingUTF8);
                if (dataString) {
                    CFDataRef data = CFStringCreateExternalRepresentation(kCFAllocatorDefault, dataString, kCFStringEncodingUTF8, 0);
                    if (data) {
                        CFDictionarySetValue(update ? update : query, kSecValueData, data);
                        CFRelease(data);
                    }
                    CFRelease(dataString);
                } else {
                    result = 1;
                    goto out;
                }
                break;
            }
            case 'f':
            {
                CFDataRef data = copyFileContents(optarg);
                CFDictionarySetValue(update ? update : query, kSecValueData, data);
                CFRelease(data);
                break;
            }
            case 'j':
                json = true;
                break;
            case 'g':
                get_password = true;
                break;
            case 'p':
                get_persistent_reference = true;
                break;
            case 'P':
            {
                NSString* dataString = CFBridgingRelease(CFStringCreateWithCString(0, optarg, kCFStringEncodingUTF8));
                if (dataString) {
                    NSData* data = [[NSData alloc] initWithBase64EncodedString:dataString options:0];
                    if (data) {
                        CFDictionarySetValue(query, kSecValuePersistentRef, (__bridge CFDataRef)data);
                    } else {
                        result = 1;
                        printf("-P expects a b64 encoded persistent reference string\n");
                        goto out;
                    }
                } else {
                    result = 1;
                    goto out;
                }
                break;
            }
            case 'q':
                if (!keychain_query_parse_cstring(query, optarg)) {
                result = 1;
                goto out;
            }
                break;
            case 'u':
            {
                bool success = true;
                if (!update)
                    update = keychain_create_query_from_string(optarg);
                else
                    success = keychain_query_parse_cstring(update, optarg);
                if (update == NULL || !success) {
                    result = 1;
                    goto out;
                }
            }
                break;
            case 'v':
                verbose = true;
                break;
            case 'l':
                limit = atoi(optarg);
                break;
            case 's':
            {
                sharingGroup = [NSString stringWithCString:optarg encoding:NSUTF8StringEncoding];
                if (!sharingGroup) {
                    result = 1;
                    goto out;
                }
                break;
            }
            case 'y':
            {
                if (!promptForAndCheckPassphrase()) {
                    result = 1;
                    goto out;
                }
                authSucceeded = true;
                break;
            }
            case 'Y':
            {
                if (!checkPassphrase(optarg, 0) ) {
                    result = 1;
                    goto out;
                }
                authSucceeded = true;
                break;
            }
            case '?':
            default:
                /* Return 2 triggers usage message. */
                result = 2;
                goto out;
		}
	}

    if (!authSucceeded && authRequired()) {
        result = 1;
        goto out;
    }

    if (sharingGroup != nil && (!query || do_add || do_delete || update)) {
        // Sharing an item with a group searches for the original item,
        // which can't be done together with a different mode.
        result = 2;
        goto out;
    }

    if (((do_add || do_delete) && (get_password || update)) || !query) {
        result = 2;
        goto out;
    }

	argc -= optind;
	argv += optind;

    int ix;
    for (ix = 0; ix < argc; ++ix) {
        if (!keychain_query_parse_cstring(query, argv[ix])) {
            result = 1;
            goto out;
        }
    }

    if (!update && !do_add && !do_delete) {
        CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
        if(limit) {
            CFNumberRef cfLimit = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &limit);
            CFDictionarySetValue(query, kSecMatchLimit, cfLimit);
            CFReleaseSafe(cfLimit);
        } else {
            CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);
        }
        if (get_password) {
            CFDictionarySetValue(query, kSecReturnData, kCFBooleanTrue);
        }
    }


    if (verbose) {
        if(json) {
            display_results_json(query);
        } else {
            CFShow(query);
        }
    }

    OSStatus error;
    if (do_add) {

        if (get_persistent_reference) {
            CFDictionarySetValue(query, kSecReturnPersistentRef, kCFBooleanTrue);
        }
        error = SecItemAdd(query, NULL);
        if (error) {
            sec_perror("SecItemAdd", error);
            print_error(error);
            result = 1;
        }
    } else if (update) {
        error = SecItemUpdate(query, update);
        if (error) {
            sec_perror("SecItemUpdate", error);
            print_error(error);
            result = 1;
        }
    } else if (do_delete) {

        error = SecItemDelete(query);
        if (error) {
            sec_perror("SecItemDelete", error);
            print_error(error);
            result = 1;
        }
    }
    else if (sharingGroup != nil) {
        CFErrorRef rawLocalError = NULL;
        id sharedItems = CFBridgingRelease(SecItemShareWithGroup(query, (__bridge CFStringRef)sharingGroup, &rawLocalError));
        NSError *localError = CFBridgingRelease(rawLocalError);
        if (!sharedItems) {
            NSString *message = [NSString stringWithFormat:@"SecItemShareWithGroup: %@", localError];
            sec_error("%s", message.UTF8String);
            result = 1;
        } else if (json) {
            display_results_json((__bridge CFTypeRef)sharedItems);
        }
        else {
            display_results((__bridge CFTypeRef)sharedItems);
        }
    }
    else {
        if (!do_delete && CFDictionaryGetValue(query, kSecUseAuthenticationUI) == NULL) {
            CFDictionarySetValue(query, kSecUseAuthenticationUI, kSecUseAuthenticationUISkip);
        }
        if (get_persistent_reference) {
            CFDictionarySetValue(query, kSecReturnPersistentRef, kCFBooleanTrue);
        }

        CFTypeRef results = NULL;
        OSStatus status = SecItemCopyMatching(query, &results);
        if (status) {
            sec_perror("SecItemCopyMatching", status);
            print_error(status);
            if (status != errSecItemNotFound) {
                result = 1;
            }
        } else if(json) {
            display_results_json(results);
        } else {
            display_results(results);
        }
        CFReleaseNull(results);
    }

out:
    CFReleaseSafe(query);
    CFReleaseSafe(update);
	return result;
}

static int
keychain_find_or_delete_generic_password(Boolean do_delete,
	int argc, char * const *argv)
{
	char *serviceName = NULL, *accountName = NULL;
	int ch, result = 0;
	Boolean get_password = FALSE;
	bool authSucceeded = false;

	while ((ch = getopt(argc, argv, "a:s:gyY:")) != -1)
	{
		switch  (ch)
		{
        case 'a':
            accountName = optarg;
            break;
        case 'g':
            if (do_delete)
                return SHOW_USAGE_MESSAGE;
			get_password = TRUE;
			break;
		case 's':
			serviceName = optarg;
			break;
		case 'y':
			if (!promptForAndCheckPassphrase()) {
				return 1;
			}
			authSucceeded = true;
			break;
		case 'Y':
			if (!checkPassphrase(optarg, 0) ) {
				return 1;
			}
			authSucceeded = true;
			break;
        case '?':
		default:
			return SHOW_USAGE_MESSAGE;
		}
	}

	if (!authSucceeded && authRequired()) {
		return 1;
	}

	result = do_keychain_find_or_delete_generic_password(do_delete,
		serviceName, accountName, get_password);

	return result;
}

int
keychain_find_generic_password(int argc, char * const *argv) {
    return keychain_find_or_delete_generic_password(0, argc, argv);
}

int
keychain_delete_generic_password(int argc, char * const *argv) {
    return keychain_find_or_delete_generic_password(1, argc, argv);
}

int keychain_item_digest(int argc, char * const *argv) {
    NSString *itemClass = @"inet";
    NSString *accessGroup = @"com.apple.ProtectedCloudStorage";

    dispatch_semaphore_t sema = dispatch_semaphore_create(0);

    if (argc == 3) {
        itemClass = [NSString stringWithUTF8String:argv[1]];
        accessGroup = [NSString stringWithUTF8String:argv[2]];
    }

    _SecItemFetchDigests(itemClass, accessGroup, ^(NSArray *items, NSError *error) {
        for (NSDictionary *item in items) {
            for (NSString *key in item) {
                printf("%s\n", [[NSString stringWithFormat:@"%@\t\t%@", key, item[key]] UTF8String]);
            }
        }
        if (error) {
            printf("%s\n", [[NSString stringWithFormat:@"Failed to find items (%@/%@): %@", itemClass, accessGroup, error] UTF8String]);
        }
        dispatch_semaphore_signal(sema);
    });
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

    return 0;
}


#if TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR

int
keychain_roll_keys(int argc, char * const *argv) {
	int ch, result = 0;
    bool force = false;

	while ((ch = getopt(argc, argv, "f")) != -1)
	{
		switch  (ch)
		{
            case 'f':
                force = true;
                break;
            default:
                return SHOW_USAGE_MESSAGE;
        }
    }
    // argc -= optind;
    // argv += optind;

    (void) argc; // These are set so folks could use them
    (void) argv; // silence the analyzer since they're not used

    CFErrorRef error = NULL;
    bool ok = _SecKeychainRollKeys(force, &error);

    fprintf(stderr, "Keychain keys up to date: %s\n", ok ? "yes" : "no");
    if (!ok && error) {
        result = (int)CFErrorGetCode(error);
        CFShow(error);
    }

    return result;
}

#endif
