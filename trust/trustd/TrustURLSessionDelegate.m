/*
 * Copyright (c) 2018-2020 Apple Inc. All Rights Reserved.
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
 */

#import <AssertMacros.h>
#import <Foundation/Foundation.h>
#include <mach/mach_time.h>
#include <utilities/SecCFWrappers.h>
#include <Security/SecInternalReleasePriv.h>
#include "TrustURLSessionCache.h"
#include "TrustURLSessionDelegate.h"

#define MAX_TASKS 3
#define MAX_TIMEOUTS 2
#define TIMEOUT_BACKOFF 60 // 1 minute
#define MAX_AGE_DEFAULT 60.0 * 60.0 * 24.0 * 1 // 1 day
#define MAX_AGE_MIN 60.0 * 60.0 // 1 hour
#define MAX_AGE_MAX 60.0 * 60.0 * 24.0 * 7 // 7 days

/* There has got to be an easier way to do this.  For now we based this code
 on CFNetwork/Connection/URLResponse.cpp. */
static CFStringRef copyParseMaxAge(CFStringRef cacheControlHeader) {
    if (!cacheControlHeader) { return NULL; }

    /* The format of the cache control header is a comma-separated list, but
     each list element could be a key-value pair, with the value quoted and
     possibly containing a comma. */
    CFStringInlineBuffer inlineBuf = {};
    CFRange componentRange;
    CFIndex length = CFStringGetLength(cacheControlHeader);
    bool done = false;
    CFCharacterSetRef whitespaceSet = CFCharacterSetGetPredefined(kCFCharacterSetWhitespace);
    CFStringRef maxAgeValue = NULL;

    CFStringInitInlineBuffer(cacheControlHeader, &inlineBuf, CFRangeMake(0, length));
    componentRange.location = 0;

    while (!done) {
        bool inQuotes = false;
        bool foundComponentStart = false;
        CFIndex charIndex = componentRange.location;
        CFIndex componentEnd = -1;
        CFRange maxAgeRg;
        componentRange.length = 0;

        while (charIndex < length) {
            UniChar ch = CFStringGetCharacterFromInlineBuffer(&inlineBuf, charIndex);
            if (!inQuotes && ch == ',') {
                componentRange.length = charIndex - componentRange.location;
                break;
            }
            if (!CFCharacterSetIsCharacterMember(whitespaceSet, ch)) {
                if (!foundComponentStart) {
                    foundComponentStart = true;
                    componentRange.location = charIndex;
                } else {
                    componentEnd = charIndex;
                }
                if (ch == '\"') {
                    inQuotes = (inQuotes == false);
                }
            }
            charIndex ++;
        }

        if (componentEnd == -1) {
            componentRange.length = charIndex - componentRange.location;
        } else {
            componentRange.length = componentEnd - componentRange.location + 1;
        }

        if (charIndex == length) {
            /* Fell off the end; this is the last component. */
            done = true;
        }

        /* componentRange should now contain the range of the current
         component; trimmed of any whitespace. */

        /* We want to look for a max-age value. */
        if (!maxAgeValue && CFStringFindWithOptions(cacheControlHeader, CFSTR("max-age"), componentRange, kCFCompareCaseInsensitive | kCFCompareAnchored, &maxAgeRg)) {
            CFIndex equalIdx;
            CFIndex maxCompRg = componentRange.location + componentRange.length;
            for (equalIdx = maxAgeRg.location + maxAgeRg.length; equalIdx < maxCompRg; equalIdx ++) {
                UniChar equalCh = CFStringGetCharacterFromInlineBuffer(&inlineBuf, equalIdx);
                if (equalCh == '=') {
                    // Parse out max-age value
                    equalIdx ++;
                    while (equalIdx < maxCompRg && CFCharacterSetIsCharacterMember(whitespaceSet, CFStringGetCharacterAtIndex(cacheControlHeader, equalIdx))) {
                        equalIdx ++;
                    }
                    if (equalIdx < maxCompRg) {
                        CFReleaseNull(maxAgeValue);
                        maxAgeValue = CFStringCreateWithSubstring(kCFAllocatorDefault, cacheControlHeader, CFRangeMake(equalIdx, maxCompRg-equalIdx));
                    }
                } else if (!CFCharacterSetIsCharacterMember(whitespaceSet, equalCh)) {
                    // Not a valid max-age header; break out doing nothing
                    break;
                }
            }
        }

        if (!done && maxAgeValue) {
            done = true;
        }
        if (!done) {
            /* Advance to the next component; + 1 to get past the comma. */
            componentRange.location = charIndex + 1;
        }
    }

    return maxAgeValue;
}

@implementation TrustURLSessionContext
- (instancetype)initWithContext:(CFTypeRef)context uris:(NSArray <NSURL *>*)uris
{
    if (self = [super init]) {
        self.context = (void *)CFRetainSafe(context);
        self.URIs = uris;
        self.URIix = 0;
        self.numTasks = 0;
        self.attribution = NSURLRequestAttributionDeveloper;
    }
    return self;
}

- (void)dealloc
{
    if (self.context) {
        CFRelease(self.context);
        self.context = NULL;
    }
}
@end

NSString *kSecTrustRequestHeaderUUID = @"X-Apple-Request-UUID";

@implementation NSURLRequest (TrustURLRequest)
- (NSUUID *)taskId {
    NSString *uuidString = [[self allHTTPHeaderFields] objectForKey:kSecTrustRequestHeaderUUID];
    NSUUID *uuid = nil;
    if (uuidString) {
        uuid = [[NSUUID alloc] initWithUUIDString:uuidString];
    }

    return uuid;
}
@end

@interface TimeoutEntry : NSObject
@property NSDate *lastAttemptDate;
@property NSUInteger timeoutCounter;
@end

@implementation TimeoutEntry
- (instancetype)init
{
    if (self = [super init]) {
        self.lastAttemptDate = [NSDate date];
        self.timeoutCounter = 1;
    }
    return self;
}
@end

@interface TrustURLSessionDelegate()
@property NSMutableDictionary <NSUUID *, TrustURLSessionContext *>* _taskContextMap;
@property NSMutableDictionary <NSString *, TimeoutEntry *>* _serverMap;
@property NSMutableDictionary <NSUUID *, dispatch_source_t>* _timerMap;
/*
 after getting a response:
 1. If no timeout and server is in map, remove the server from the map
 2. If timeout and server is not in map, add to map, setting date to now and counter to 1
 3. If timeout and server is in map, set date to now and add + 1 to counter

 In terms of deciding whether to make a request:
 1. If not in map, go for it
 2. If in map and counter < MAX_TIMEOUTS, go for it
 3. If in map and counter > MAX_TIMEOUTS and date > TIMEOUT_BACKOFF ago, go for it
 4. otherwise, no network
 */
@end

@implementation TrustURLSessionDelegate
- (id)init {
    /* Protect future developers from themselves */
    if ([self class] == [TrustURLSessionDelegate class]) {
        NSException *e = [NSException exceptionWithName:@"AbstractClassException"
                                                 reason:@"This is an abstract class. To use it, please subclass."
                                               userInfo:nil];
        @throw e;
    } else {
        self._taskContextMap = [NSMutableDictionary dictionary];
        self._serverMap = [NSMutableDictionary dictionary];
        self._timerMap = [NSMutableDictionary dictionary];
        self.queue = dispatch_queue_create("com.apple.trustd.TrustURLSessionDelegate", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
        return [super init];
    }
}

- (TrustURLSessionContext *)contextForTask:(NSUUID *)taskId
{
    @synchronized (self._taskContextMap) {
        return [self._taskContextMap objectForKey:taskId];
    }
}

- (void)removeTask:(NSUUID *)taskId
{
    @synchronized (self._taskContextMap) {
        [self._taskContextMap removeObjectForKey:taskId];
    }
}

- (NSUUID *)addTask:(TrustURLSessionContext *)context
{
    NSUUID *uuid = [NSUUID UUID];
    @synchronized (self._taskContextMap) {
        [self._taskContextMap setObject:context forKey:uuid];
    }
    return uuid;
}

- (void)cancelTimer:(NSUUID *)taskId
{
    @synchronized (self._timerMap) {
        dispatch_source_t timer = [self._timerMap objectForKey:taskId];
        if (timer) {
            dispatch_source_cancel(timer);
            [self._timerMap removeObjectForKey:taskId];
        }
    }
}

- (dispatch_source_t)createTimerForTask:(NSUUID *)taskId
{
    dispatch_source_t timeoutTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, self.queue);
    dispatch_source_set_timer(timeoutTimer, dispatch_time(DISPATCH_TIME_NOW, TrustURLSessionGetResourceTimeout()*NSEC_PER_SEC), DISPATCH_TIME_FOREVER, 0);
    @synchronized (self._timerMap) {
        [self cancelTimer:taskId]; // cancel any existing for this task
        [self._timerMap setObject:timeoutTimer forKey:taskId];
    }
    return timeoutTimer;
}

- (void)removeServer:(NSString *)server
{
    /* If this is Apple's OCSP responder, we need to unmunge the hostname, since
     * we use the pre-munged hostname to do the timeout entry lookup in fetchNext. */
    if ([server isEqualToString:@"ocsp2.apple.com"]) {
        server = @"ocsp.apple.com";
    }
    @synchronized (self._serverMap) {
        [self._serverMap removeObjectForKey:server];
    }
}

- (void)addServer:(NSString *)server
{
    TimeoutEntry *timeoutEntry = [[TimeoutEntry alloc] init];
    @synchronized (self._serverMap) {
        self._serverMap[server] = timeoutEntry;
    }
}

- (void)incrementCountForServer:(NSString *)server
{
    /* If this is Apple's OCSP responder, we need to unmunge the hostname, since
     * we use the pre-munged hostname to do the timeout entry lookup in fetchNext. */
    if ([server isEqualToString:@"ocsp2.apple.com"]) {
        server = @"ocsp.apple.com";
    }
    @synchronized (self._serverMap) {
        TimeoutEntry *entry = self._serverMap[server];
        if (!entry) {
            [self addServer:server];
        } else {
            entry.timeoutCounter += 1;
            entry.lastAttemptDate = [NSDate date];
            self._serverMap[server] = entry;
        }
    }
}

- (TimeoutEntry *)timeoutEntryForServer:(NSString *)server
{
    @synchronized (self._serverMap) {
        TimeoutEntry *entry = self._serverMap[server];
        return entry;
    }
}

- (NSURLRequest *)createNextRequest:(NSURL *)uri context:(TrustURLSessionContext *)context {
    NSURLComponents *components = [NSURLComponents componentsWithURL:uri resolvingAgainstBaseURL:YES];
    /* For Apple ocsp responders, use https instead of http */
    if ([[components host] isEqualToString:@"ocsp-uat.corp.apple.com"]) {
        secdebug("http", "replacing http test ocsp responder URI with https");
        components.scheme = @"https";
    } else if ([[components host] isEqualToString:@"ocsp.apple.com"]) {
        secdebug("http", "replacing http prod ocsp responder URI with https");
        components.scheme = @"https";
        components.host = @"ocsp2.apple.com";
    }
    NSURL *requestUri = components.URL;

    NSUUID *taskId = [self addTask:context];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:requestUri];
    [request addValue:[taskId UUIDString] forHTTPHeaderField:kSecTrustRequestHeaderUUID];
    request.attribution = context.attribution;
    return request;
}

- (BOOL)fetchNext:(NSURLSession *)session context:(TrustURLSessionContext *)context {
    if (context.numTasks >= MAX_TASKS) {
        secnotice("http", "Too many fetch %@ requests for this cert", [self class]);
        return true;
    }

    for (NSUInteger ix = context.URIix; ix < [context.URIs count]; ix++) {
        NSURL *uri = context.URIs[ix];
        TimeoutEntry *timeoutEntry = [self timeoutEntryForServer:uri.host];
        if (!timeoutEntry || // no recent timeout
            timeoutEntry.timeoutCounter < MAX_TIMEOUTS || // too few recent timeouts
            [timeoutEntry.lastAttemptDate timeIntervalSinceNow] < -TIMEOUT_BACKOFF) { // last timeout not recent enough
            if ([[uri scheme] isEqualToString:@"http"]) {
                context.URIix = ix + 1; // Next time we'll start with the next index
                context.numTasks++;
                NSURLSessionTask *task = [session dataTaskWithRequest:[self createNextRequest:uri context:context]];

                /* We want to return to callers within a short(ish) time period to avoid significant hangs
                 * in UIs, but if we give the task this timeout, we can get into pathological cases where
                 * we just keep trying to establish the connection but the task times out and is cancelled.
                 * So we have the task use the default timeouts so it has plenty of time to make connections
                 * that we can re-use later, but trigger our own shorter timeout to finish the evaluation. */
                dispatch_source_t timeoutTimer = [self createTimerForTask:[task.originalRequest taskId]];
                dispatch_source_set_event_handler(timeoutTimer, ^{
                    // Create our own timeout error (similar to but distinct from the NSURLSession one)
                    secerror("trustd triggered evaluation timeout for taskId %@", [task.originalRequest taskId]);
                    NSError *timeoutError = [NSError errorWithDomain:NSURLErrorDomain
                                                                code:NSURLErrorTimedOut
                                                            userInfo:@{
                        NSURLErrorFailingURLStringErrorKey : [uri absoluteString],
                        NSDebugDescriptionErrorKey : [NSString stringWithFormat:@"(trustd) The request timed out: %@", task.description]
                    }];
                    // Call didCompleteWithError to handle the timeout
                    [self URLSession:session task:task didCompleteWithError:timeoutError];
                });
                dispatch_resume(timeoutTimer);
                [task resume];
                secinfo("http", "request for uri: %@", uri);
                return false; // we scheduled a job
            } else {
                secnotice("http", "skipping unsupported scheme %@", [uri scheme]);
            }
        } else {
            secnotice("http", "skipping host due to too many recent timeouts: %@", uri.host);
        }
    }

    /* No more issuers left to try, we're done. Report that no async jobs were started. */
    secdebug("http", "no request issued");
    return true;
}

- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)dataTask didReceiveData:(NSData *)data {
    /* Append the data to the response data*/
    NSUUID *taskId = [dataTask.originalRequest taskId];
    TrustURLSessionContext *context = [self contextForTask:taskId];
    if (!context) {
        secnotice("http", "failed to find task for taskId: %@", taskId);
        return;
    }

    secdebug("http", "received data for taskId %@", taskId);
    if (!context.response) {
        context.response = [NSMutableData data];
    }
    [context.response appendData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error {
    /* Protect future developers from themselves */
    if ([self class] == [TrustURLSessionDelegate class]) {
        NSException *e = [NSException exceptionWithName:@"AbstractClassException"
                                                 reason:@"This is an abstract class. To use it, please subclass and override didCompleteWithError."
                                               userInfo:nil];
        @throw e;
    } else {
        NSUUID *taskId = [task.originalRequest taskId];
        [self cancelTimer:taskId];
        TrustURLSessionContext *context = [self contextForTask:taskId];
        if (!context) {
            secnotice("http","failed to find task for taskId: %@", taskId);
            return;
        }

        secdebug("http", "completed taskId %@", taskId);
        context.maxAge = MAX_AGE_DEFAULT; /* Default is 1 days */
        if ([context.response length] > 0 && [[task response] isKindOfClass:[NSHTTPURLResponse class]]) {
            NSString *cacheControl = [[(NSHTTPURLResponse *)[task response] allHeaderFields] objectForKey:@"cache-control"];
            NSString *maxAge = CFBridgingRelease(copyParseMaxAge((__bridge CFStringRef)cacheControl));
            if (maxAge && ([maxAge doubleValue] >= MAX_AGE_MIN) && ([maxAge doubleValue] <= MAX_AGE_MAX)) {
                context.maxAge = [maxAge doubleValue];
            }
        }

        // Update server map for timeout backoffs
        NSString *host = task.originalRequest.URL.host;
        if (host && error && [error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorTimedOut) {
            // timeout error
            secdebug("http", "incrementing timeout counter for %@", host);
            [self incrementCountForServer:host];
        } else if (host) {
            secdebug("http", "removing timeout entry for %@", host);
            [self removeServer:host];
        }
    }
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
willPerformHTTPRedirection:(NSHTTPURLResponse *)redirectResponse
        newRequest:(NSURLRequest *)request
 completionHandler:(void (^)(NSURLRequest *))completionHandler {
    /* The old code didn't allow re-direction, so we won't either. */
    secnotice("http", "failed redirection for %@", task.originalRequest.URL);
    completionHandler(nil);
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
 completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential * _Nullable))completionHandler
{
    if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        /* Disable networking during trust evaluation to avoid recursion */
        secdebug("http", "server using TLS; disabling network for trust evaluation");
        SecTrustRef trust = challenge.protectionSpace.serverTrust;
        OSStatus status = SecTrustSetNetworkFetchAllowed(trust, false);
        if (status != errSecSuccess) {
            goto cancel;
        }

        CFErrorRef error = nil;
        if (!SecTrustEvaluateWithError(trust, &error)) {
            secerror("failed to connect to server: %@", error);
            CFReleaseNull(error);
            goto cancel;
        } else {
            /* avoid calling NSURLSessionAuthChallengeUseCredential inside trustd,
             * as it can invoke a direct trust evaluation which might be blocked
             * by a queued operation on the same trust reference: rdar://112939771
             * i.e. don't do this:
             * completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust: trust]);
             */
            completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
        }
        return;

    cancel:
        completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, NULL);
        return;

    } else {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, NULL);
    }
}
@end
