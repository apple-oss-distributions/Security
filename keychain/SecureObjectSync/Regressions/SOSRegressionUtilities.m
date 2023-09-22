/*
 * Copyright (c) 2012-2014 Apple Inc. All Rights Reserved.
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
//  SOSRegressionUtilities.c
//

#include <AssertMacros.h>
#include <stdio.h>
#include <Security/SecItem.h>

#include <utilities/SecCFWrappers.h>
#include <utilities/debugging.h>

#include "keychain/SecureObjectSync/SOSAccount.h"
#include "keychain/SecureObjectSync/SOSAccountPriv.h"
#include "keychain/SecureObjectSync/SOSCircle.h"
#include "keychain/SecureObjectSync/SOSInternal.h"
#include "keychain/SecureObjectSync/SOSPeerInfoInternal.h"
#include "keychain/SecureObjectSync/SOSPeerInfoPriv.h"

#include "keychain/SecureObjectSync/CKBridge/SOSCloudKeychainClient.h"
#include "SOSRegressionUtilities.h"
#include "keychain/SecureObjectSync/SOSInternal.h"

#if TARGET_OS_IPHONE
#include <MobileGestalt.h>
#endif

static const uint64_t maxTimeToWaitInSeconds = 30ull * NSEC_PER_SEC;

// MARK: ----- SOS General -----

const char *cloudKeychainProxyPath = "/System/Library/Frameworks/Security.framework/Resources/CloudKeychainProxy.bundle/CloudKeychainProxy";

static const char *basecfabsoluteTimeToString(CFAbsoluteTime abstime, CFTimeZoneRef tz)
{
    CFGregorianDate greg = CFAbsoluteTimeGetGregorianDate(abstime, NULL);
    char str[20];
    if (19 != snprintf(str, 20, "%4.4d-%2.2d-%2.2d_%2.2d:%2.2d:%2.2d",
        (int)greg.year, greg.month, greg.day, greg.hour, greg.minute, (int)greg.second))
        str[0]=0;
    char *data = (char *)malloc(20);
    strncpy(data, str, 20);
    return data;
}

const char *cfabsoluteTimeToString(CFAbsoluteTime abstime)
{
    return basecfabsoluteTimeToString(abstime, NULL);
}

const char *cfabsoluteTimeToStringLocal(CFAbsoluteTime abstime)
{
    // Caller must release using free
    CFDateFormatterRef formatter = NULL;
    CFTimeZoneRef tz = NULL;
	CFLocaleRef locale = NULL;
    CFDateRef date = NULL;
    CFStringRef cftime_string = NULL;
    char *time_string = NULL;
    char buffer[1024] = {0,};
    size_t sz;
    
    require(tz = CFTimeZoneCopySystem(), xit);
    require(locale = CFLocaleCreate(NULL, CFSTR("en_US")), xit);
    
    require(formatter = CFDateFormatterCreate(kCFAllocatorDefault, locale, kCFDateFormatterShortStyle, kCFDateFormatterShortStyle), xit);
    CFDateFormatterSetFormat(formatter, CFSTR("MM/dd/yy HH:mm:ss.SSS zzz"));
    require(date = CFDateCreate(kCFAllocatorDefault, abstime), xit);
    require(cftime_string = CFDateFormatterCreateStringWithDate(kCFAllocatorDefault, formatter, date), xit);

    CFStringGetCString(cftime_string, buffer, 1024, kCFStringEncodingUTF8);
    sz = strnlen(buffer, 1024);
    time_string = (char *)malloc(sz);
    strncpy(time_string, buffer, sz+1);
xit:
    CFReleaseSafe(tz);
    CFReleaseSafe(formatter);
    CFReleaseSafe(locale);
    CFReleaseSafe(date);
    CFReleaseSafe(cftime_string);
    return time_string;
}

#include <sys/stat.h>

static int file_exist (const char *filename)
{
    struct stat buffer;   
    return (stat (filename, &buffer) == 0);
}

bool XPCServiceInstalled(void)
{
    return file_exist(cloudKeychainProxyPath);
}

void registerForKVSNotifications(const void *observer, CFStringRef name, CFNotificationCallback callBack)
{
    // observer is basically a context; name may not be null
    CFNotificationCenterRef center = CFNotificationCenterGetDarwinNotifyCenter();
    CFNotificationSuspensionBehavior suspensionBehavior = CFNotificationSuspensionBehaviorDeliverImmediately;    //ignored?
    CFNotificationCenterAddObserver(center, observer, callBack, name, NULL, suspensionBehavior);
}

bool testPutObjectInCloudAndSync(CFStringRef key, CFTypeRef object, CFErrorRef *error, dispatch_group_t dgroup, dispatch_queue_t processQueue)
{
    bool result = testPutObjectInCloud(key, object, error, dgroup, processQueue);
    testSynchronize(processQueue, dgroup);

    return result;
}

bool testPutObjectInCloud(CFStringRef key, CFTypeRef object, CFErrorRef *error, dispatch_group_t dgroup, dispatch_queue_t processQueue)
{
    secnotice("test", "testPutObjectInCloud: key: %@, %@", key, object);
    CFDictionaryRef objects = CFDictionaryCreateForCFTypes(kCFAllocatorDefault, key, object, NULL);
    if (objects)
    {
        dispatch_group_enter(dgroup);
        SOSCloudKeychainPutObjectsInCloud(objects, processQueue, ^ (CFDictionaryRef returnedValues, CFErrorRef error)
        {
            secnotice("test", "testPutObjectInCloud returned: %@", returnedValues);
            if (error)
            {
                secnotice("test", "testPutObjectInCloud returned: %@", error);
                CFRelease(error);
            }
            dispatch_group_leave(dgroup);
        });
        CFRelease(objects);
    }

    return true;
}

CFTypeRef testGetObjectFromCloud(CFStringRef key, dispatch_queue_t processQueue, dispatch_group_t dgroup)
{
    // TODO: make sure we return NULL, not CFNull
    secnotice("test", "start");
    CFMutableArrayRef keysToGet = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
    CFArrayAppendValue(keysToGet, key);

    __block CFTypeRef object = NULL;

    dispatch_semaphore_t waitSemaphore = dispatch_semaphore_create(0);
    dispatch_time_t finishTime = dispatch_time(DISPATCH_TIME_NOW, maxTimeToWaitInSeconds);

    dispatch_group_enter(dgroup);
    SOSCloudKeychainGetObjectsFromCloud(keysToGet, processQueue, ^ (CFDictionaryRef returnedValues, CFErrorRef error)
    {
        secnotice("test", "SOSCloudKeychainGetObjectsFromCloud returned: %@", returnedValues);
        if (returnedValues)
        {
            object = (CFTypeRef)CFDictionaryGetValue(returnedValues, key);
            if (object)
                CFRetain(object);
        }
        if (error)
        {
            secerror("SOSCloudKeychainGetObjectsFromCloud returned error: %@", error);
     //       CFRelease(*error);
        }
        dispatch_group_leave(dgroup);
        secnotice("test", "SOSCloudKeychainGetObjectsFromCloud block exit: %@", object);
        dispatch_semaphore_signal(waitSemaphore);
    });
    
	dispatch_semaphore_wait(waitSemaphore, finishTime);
    if (object && (CFGetTypeID(object) == CFNullGetTypeID()))   // return a NULL instead of a CFNull
    {
        CFRelease(object);
        object = NULL;
    }
    secnotice("test", "returned: %@", object);
    return object;
}

CFTypeRef testGetObjectsFromCloud(CFArrayRef keysToGet, dispatch_queue_t processQueue, dispatch_group_t dgroup)
{
    __block CFTypeRef object = NULL;

    dispatch_semaphore_t waitSemaphore = dispatch_semaphore_create(0);
    dispatch_time_t finishTime = dispatch_time(DISPATCH_TIME_NOW, maxTimeToWaitInSeconds);
    dispatch_group_enter(dgroup);

    CloudKeychainReplyBlock replyBlock =
        ^ (CFDictionaryRef returnedValues, CFErrorRef error)
    {
        secnotice("test", "SOSCloudKeychainGetObjectsFromCloud returned: %@", returnedValues);
        object = returnedValues;
        if (object)
            CFRetain(object);
        if (error)
        {
            secerror("SOSCloudKeychainGetObjectsFromCloud returned error: %@", error);
        }
        dispatch_group_leave(dgroup);
        secnotice("test", "SOSCloudKeychainGetObjectsFromCloud block exit: %@", object);
        dispatch_semaphore_signal(waitSemaphore);
    };
    
    if (!keysToGet) {
        SOSCloudKeychainGetAllObjectsFromCloud(processQueue, replyBlock);
    } else {
        SOSCloudKeychainGetObjectsFromCloud(keysToGet, processQueue, replyBlock);
    }

	dispatch_semaphore_wait(waitSemaphore, finishTime);
    if (object && (CFGetTypeID(object) == CFNullGetTypeID()))   // return a NULL instead of a CFNull
    {
        CFRelease(object);
        object = NULL;
    }
    secnotice("test", "returned: %@", object);
    return object;
}

bool testSynchronize(dispatch_queue_t processQueue, dispatch_group_t dgroup)
{
    __block bool result = false;
    dispatch_semaphore_t waitSemaphore = dispatch_semaphore_create(0);
    dispatch_time_t finishTime = dispatch_time(DISPATCH_TIME_NOW, maxTimeToWaitInSeconds);

    dispatch_group_enter(dgroup);

    SOSCloudKeychainSynchronize(processQueue, ^(CFDictionaryRef returnedValues, CFErrorRef error)
        {
            result = true;
            dispatch_group_leave(dgroup);
            dispatch_semaphore_signal(waitSemaphore);
        });
    
	dispatch_semaphore_wait(waitSemaphore, finishTime);
    return result;
}

bool testClearAll(dispatch_queue_t processQueue, dispatch_group_t dgroup)
{
    __block bool result = false;
    dispatch_semaphore_t waitSemaphore = dispatch_semaphore_create(0);
    dispatch_time_t finishTime = dispatch_time(DISPATCH_TIME_NOW, maxTimeToWaitInSeconds);

    dispatch_group_enter(dgroup);

    secnotice("circleOps", "SOSCloudKeychainClearAll called by testClearAll");
    SOSCloudKeychainClearAll(processQueue, ^(CFDictionaryRef returnedValues, CFErrorRef error)
        {
            result = true;
            secnotice("test", "SOSCloudKeychainClearAll returned: %@", error);
            dispatch_group_leave(dgroup);
            dispatch_semaphore_signal(waitSemaphore);
        });
    
	dispatch_semaphore_wait(waitSemaphore, finishTime);
    secnotice("test", "SOSCloudKeychainClearAll exit");
    return result;
}

void unregisterFromKVSNotifications(const void *observer)
{
    CFNotificationCenterRemoveEveryObserver(CFNotificationCenterGetDarwinNotifyCenter(), observer);
}

//
// MARK: SOSPeerInfo creation helpers
//

CFDictionaryRef SOSCreatePeerGestaltFromName(CFStringRef name)
{
    return CFDictionaryCreateForCFTypes(kCFAllocatorDefault,
                                        kPIUserDefinedDeviceNameKey, name,
                                        NULL);
}


SOSPeerInfoRef SOSCreatePeerInfoFromName(CFStringRef name,
                                         SecKeyRef* outSigningKey,
                                         SecKeyRef* outOctagonSigningKey,
                                         SecKeyRef* outOctagonEncryptionKey,
                                         CFErrorRef *error)
{
    SOSPeerInfoRef result = NULL;
    SecKeyRef publicKey = NULL;
    SecKeyRef octagonSigningPublicKey = NULL;
    SecKeyRef octagonEncryptionPublicKey = NULL;
    CFDictionaryRef gestalt = NULL;

    require(outSigningKey, exit);

    require_quiet(SecError(GeneratePermanentECPair(256, &publicKey, outSigningKey), error, CFSTR("Failed To Create Key")), exit);
    require_quiet(SecError(GeneratePermanentECPair(384, &octagonSigningPublicKey, outOctagonSigningKey), error, CFSTR("Failed to Create Octagon Signing Key")), exit);
    require_quiet(SecError(GeneratePermanentECPair(384, &octagonEncryptionPublicKey, outOctagonEncryptionKey), error, CFSTR("Failed to Create Octagon Encryption Key")), exit);

    gestalt = SOSCreatePeerGestaltFromName(name);
    require(gestalt, exit);

    result = SOSPeerInfoCreate(NULL, gestalt, NULL, *outSigningKey,
                               *outOctagonSigningKey, *outOctagonEncryptionKey,
                               // Always support CKKS4All for now
                               true,
                               error);

exit:
    CFReleaseNull(gestalt);
    CFReleaseNull(publicKey);
    CFReleaseNull(octagonSigningPublicKey);
    CFReleaseNull(octagonEncryptionPublicKey);

    return result;
}

SOSFullPeerInfoRef SOSCreateFullPeerInfoFromName(CFStringRef name,
                                                 SecKeyRef* outSigningKey,
                                                 SecKeyRef* outOctagonSigningKey,
                                                 SecKeyRef* outOctagonEncryptionKey,
                                                 CFErrorRef *error)
{
    SOSFullPeerInfoRef result = NULL;
    SecKeyRef publicKey = NULL;
    CFDictionaryRef gestalt = NULL;

    gestalt = SOSCreatePeerGestaltFromName(name);
    require(gestalt, exit);

    require(outSigningKey, exit);
    *outSigningKey = GeneratePermanentFullECKey(256, name, error);
    require(*outSigningKey, exit);
        
    if(outOctagonSigningKey && outOctagonEncryptionKey) {
        require(outOctagonSigningKey, exit);
        *outOctagonSigningKey = GeneratePermanentFullECKey(384, name, error);
        require(*outOctagonSigningKey, exit);

        require(outOctagonEncryptionKey, exit);
        *outOctagonEncryptionKey = GeneratePermanentFullECKey(384, name, error);
        require(*outOctagonEncryptionKey, exit);
        result = SOSFullPeerInfoCreate(NULL, gestalt, name,
                                       NULL,
                                       *outSigningKey,
                                       *outOctagonSigningKey,
                                       *outOctagonEncryptionKey,
                                       error);
    } else {
        result = SOSFullPeerInfoCreate(NULL, gestalt, name,
                                   NULL,
                                   *outSigningKey,
                                   NULL,
                                   NULL,
                                   error);
    }

exit:
    CFReleaseNull(gestalt);
    CFReleaseNull(publicKey);

    return result;
}

// MARK: ----- Circle/Peer Creators and Authenticators

SOSFullPeerInfoRef SOSTestV0FullPeerInfo(CFStringRef name, SecKeyRef userKey, CFStringRef OSName, SOSPeerInfoDeviceClass devclass) {
    CFErrorRef error = NULL;
    SecKeyRef signingKey = NULL;
    SecKeyRef octagonSigningKey = NULL;
    SecKeyRef octagonEncryptionKey = NULL;
    SOSFullPeerInfoRef fpi = SOSCreateFullPeerInfoFromName(name, &signingKey, &octagonSigningKey, &octagonEncryptionKey, NULL);
    SOSPeerInfoRef pi = SOSFullPeerInfoGetPeerInfo(fpi);
    pi->version = 0;
    CFMutableDictionaryRef gestalt = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFDictionaryAddValue(gestalt, kPIUserDefinedDeviceNameKey, name);
    if(SOSPeerInfo_unknown != devclass) {
        CFDictionaryAddValue(gestalt, kPIDeviceModelNameKey, SOSModelFromType(devclass));
        CFDictionaryAddValue(gestalt, kPIOSVersionKey, OSName);
    }
    SOSFullPeerInfoUpdateGestalt(fpi, gestalt, NULL);
    if(!SOSFullPeerInfoPromoteToApplication(fpi, userKey, &error)) {
        CFReleaseNull(fpi);
    }
    CFReleaseNull(gestalt);
    return fpi;
}

SOSFullPeerInfoRef SOSTestFullPeerInfo(CFStringRef name, SecKeyRef userKey, CFStringRef OSName, SOSPeerInfoDeviceClass devclass) {
    CFErrorRef error = NULL;
    SecKeyRef signingKey = NULL;
    SecKeyRef octagonSigningKey = NULL;
    SecKeyRef octagonEncryptionKey = NULL;
    SOSFullPeerInfoRef fpi = SOSCreateFullPeerInfoFromName(name, &signingKey, &octagonSigningKey, &octagonEncryptionKey, NULL);
    CFMutableDictionaryRef gestalt = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);
    CFDictionaryAddValue(gestalt, kPIUserDefinedDeviceNameKey, name);
    if(SOSPeerInfo_unknown != devclass) {
        CFDictionaryAddValue(gestalt, kPIDeviceModelNameKey, SOSModelFromType(devclass));
        CFDictionaryAddValue(gestalt, kPIOSVersionKey, OSName);
    }
    SOSFullPeerInfoUpdateGestalt(fpi, gestalt, NULL);
    if(!SOSFullPeerInfoPromoteToApplication(fpi, userKey, &error)) {
        CFReleaseNull(fpi);
    }
    CFReleaseNull(gestalt);
    return fpi;
}

// to use this function the first peer must be valid
SOSCircleRef SOSTestCircle(SecKeyRef userKey, void * firstFpiv, ... ) {
    CFErrorRef error = NULL;
    SOSFullPeerInfoRef firstFpi = (SOSFullPeerInfoRef) firstFpiv;
    SOSCircleRef circle = SOSCircleCreate(kCFAllocatorDefault, CFSTR("oak"), &error);
    CFSetAddValue(circle->peers, SOSFullPeerInfoGetPeerInfo(firstFpi));

    va_list argp;
    va_start(argp, firstFpiv);
    SOSFullPeerInfoRef fpi = NULL;
    while((fpi = va_arg(argp, SOSFullPeerInfoRef)) != NULL) {
        CFSetAddValue(circle->peers, SOSFullPeerInfoGetPeerInfo(fpi));
    }
    va_end(argp);

    SOSCircleGenerationSign(circle, userKey, firstFpi, &error);
    CFReleaseNull(error);

    return circle;
}

SecKeyRef SOSMakeUserKeyForPassword(const char *passwd) {
    CFDataRef password = CFDataCreate(NULL, (uint8_t *) passwd, strlen(passwd));
    CFErrorRef error = NULL;
    CFDataRef parameters = SOSUserKeyCreateGenerateParameters(NULL);
    SecKeyRef userKey = SOSUserKeygen(password, parameters, &error);
    CFReleaseSafe(password);
    CFReleaseNull(parameters);
    CFReleaseNull(error);
    return userKey;
}

bool SOSPeerValidityCheck(SOSFullPeerInfoRef fpi, SecKeyRef userKey, CFErrorRef *error) {
    SecKeyRef pubKey = SecKeyCopyPublicKey(userKey);
    bool retval = SOSPeerInfoApplicationVerify(SOSFullPeerInfoGetPeerInfo(fpi), pubKey, error);
    CFReleaseNull(pubKey);
    return retval;
}


// MARK: ----- MAC Address -----

/*
 *	Name:			GetHardwareAdress
 *
 *	Parameters:		None.
 *
 *	Returns:		Nothing
 *
 *	Description:	Retrieve the hardare address for a specified network interface
 *
 */

#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <unistd.h>
#include <netdb.h>
#include <sys/stat.h>

static int getHardwareAddress(const char *interfaceName, size_t maxLenAllowed, size_t *outActualLength, char *outHardwareAddress)
{
	char				*end;
	struct if_msghdr	*ifm;
	struct sockaddr_dl	*sdl;
	char				*buf;
	int				result = -1;
	size_t				buffSize;
	int					mib[6] = {CTL_NET, AF_ROUTE, 0, AF_INET, NET_RT_IFLIST, 0 };
	
	buf = 0;
	*outActualLength = 0;
	//	see how much space is needed
	require_noerr(result = sysctl(mib, 6, NULL, &buffSize, NULL, 0), xit);

	//	allocate the buffer
	require(buf = malloc(buffSize), xit);
		
	//	get the interface info	
	require_noerr(result = sysctl(mib, 6, buf, &buffSize, NULL, 0), xit);
    
	ifm = (struct if_msghdr *) buf;
	end = buf + buffSize;
	do
	{
		if (ifm->ifm_type == RTM_IFINFO) 		//	should always be true
		{
			sdl = (struct sockaddr_dl *) (ifm + 1);
			if ( sdl->sdl_nlen == strlen( interfaceName ) && ( bcmp( sdl->sdl_data, interfaceName, sdl->sdl_nlen ) == 0 ) )
			{
				if (  sdl->sdl_alen > 0 )
				{
					size_t hardwareLen;
					
					result = 0;						//	indicate found the interface
					hardwareLen = sdl->sdl_alen;
					if ( hardwareLen > maxLenAllowed )
					{
						hardwareLen = maxLenAllowed;
						result = -2;				//	indicate truncation of the address
					} 
					memcpy( outHardwareAddress, sdl->sdl_data + sdl->sdl_nlen, hardwareLen );
					*outActualLength = hardwareLen;
					break;
					
				}	
			}	
		}
		ifm = (struct if_msghdr *)  ((char*)ifm + ifm->ifm_msglen);
	} while ( (char*)ifm < end );
	
xit:
	if (buf)
		free(buf);

	return result;	
}

// MARK: ----- cloudTransportTests -----

CFStringRef myMacAddress(void)
{
    // 6 bytes, no ":"s
    CFStringRef result = NULL;
    const char *interfaceName = "en0";
    size_t maxLenAllowed = 1024;
    size_t outActualLength = 0;
    char outHardwareAddress[1024];
    
    require_noerr(getHardwareAddress(interfaceName, maxLenAllowed, &outActualLength, outHardwareAddress), xit);
    require(outActualLength==6, xit);
    unsigned char buf[32]={0,};
    
    unsigned char *ps = (unsigned char *)buf;
    unsigned char *pa = (unsigned char *)outHardwareAddress;
    for (int ix = 0; ix < 6; ix++, pa++)
        ps += snprintf((char *)ps, sizeof(buf)-(ps - buf), "%02x", *pa);

    result = CFStringCreateWithCString(kCFAllocatorDefault, (const char *)buf, kCFStringEncodingUTF8);
    
xit:
    return result;    
}

CFStringRef SOSModelFromType(SOSPeerInfoDeviceClass cls) {
    switch(cls) {
        case SOSPeerInfo_macOS: return CFSTR("Mac Pro");
        case SOSPeerInfo_iOS: return CFSTR("iPhone");
        case SOSPeerInfo_iCloud: return CFSTR("iCloud");
        case SOSPeerInfo_watchOS: return CFSTR("WatchName");
        case SOSPeerInfo_tvOS: return CFSTR("AppleTVName");
        default: return CFSTR("GENERICOSTHING");
    }
}
