/*
 * Copyright (c) 2017 Apple Inc. All Rights Reserved.
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

#import <Foundation/Foundation.h>
#include "lib/SecArgParse.h"
#import "supd/supdProtocol.h"
#import <Foundation/NSXPCConnection_Private.h>
#import <Security/SFAnalytics.h>
#import "SecInternalReleasePriv.h"

/* Internal Topic Names */
NSString* const SFAnalyticsTopicKeySync = @"KeySyncTopic";

static void nsprintf(NSString *fmt, ...) NS_FORMAT_FUNCTION(1, 2);
static void nsprintf(NSString *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    NSString *str = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);

    puts([str UTF8String]);
#if !__has_feature(objc_arc)
    [str release];
#endif
}

static NSXPCConnection* getConnection(void)
{
    NSXPCConnection* connection = [[NSXPCConnection alloc] initWithMachServiceName:@"com.apple.securityuploadd" options:0];
    connection.remoteObjectInterface = [NSXPCInterface interfaceWithProtocol:@protocol(supdProtocol)];
    [connection resume];
    return connection;
}

static void getSysdiagnoseDump(void)
{
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();
    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] getSysdiagnoseDumpWithReply:^(NSString * sysdiagnoseString) {
        nsprintf(@"Analytics sysdiagnose: \n%@", sysdiagnoseString);
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}

static void createLoggingJSON(char *topicName)
{
    NSString *topic = topicName ? [NSString stringWithUTF8String:topicName] : SFAnalyticsTopicKeySync;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();
    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] createLoggingJSON:YES topic:topic reply:^(NSData* data, NSError* error) {
        if (data) {
            // Success! Only print the JSON blob to make output easier to parse
            nsprintf(@"%@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
        } else {
            nsprintf(@"supd gave us an error: %@", error);
        }
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}

static void createChunkedLoggingJSON(char *topicName)
{
    NSString *topic = topicName ? [NSString stringWithUTF8String:topicName] : SFAnalyticsTopicKeySync;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();
    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] createChunkedLoggingJSON:YES topic:topic reply:^(NSData* data, NSError* error) {
        if (data) {
            // Success! Only print the JSON blob to make output easier to parse
            nsprintf(@"%@", [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]);
        } else {
            nsprintf(@"supd gave us an error: %@", error);
        }
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}

static void forceUploadAnalytics(void)
{
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();
    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] forceUploadWithReply:^(BOOL success, NSError *error) {
        if (success) {
            printf("Supd reports successful upload\n");
        } else {
            nsprintf(@"Supd reports failure: %@", error);
        }
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}

static void
getInfoDump(void)
{
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();
    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] clientStatus:^(NSDictionary<NSString *,id> *info, NSError *error) {
        if (info) {
            nsprintf(@"%@\n", info);
        } else {
            nsprintf(@"Supd reports failure: %@", error);
        }
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}

static void
forceOldUploadDate(void)
{
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();

    NSDate *date = [NSDate dateWithTimeIntervalSinceNow:(-7 * 24 * 3600.0)];

    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] setUploadDateWith:date reply:^(BOOL success, NSError *error) {
        if (!success && error) {
            nsprintf(@"Supd reports failure: %@", error);
        }
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}

static void
encodeSFACollection(NSString *jsonFile, NSString *outputFile)
{
    NSData *data = [NSData dataWithContentsOfFile:jsonFile];
    NSError *error = nil;

    if (data == NULL) {
        fprintf(stderr, "file have no data: %s", [jsonFile UTF8String]);
        exit(1);
    }

    NSData *encoded = [SFAnalytics encodeSFACollection:data error:&error];
    if (encoded == NULL) {
        fprintf(stderr, "error: %s\n", [[error description] UTF8String]);
        exit(1);
    }
    if (outputFile) {
        [encoded writeToFile:outputFile atomically:YES];
    } else {
        fwrite(encoded.bytes, encoded.length, 1, stdout);
    }
    return;
}

static void
printSFACollectionData(NSData *data)
{
    NSError *error;

    NSString *format = [SFAnalytics formatSFACollection:data error:&error];
    if (format == nil) {
        nsprintf(@"can't format SFACollection: %@", error);
        return;
    }
    nsprintf(@"%@", format);
}

static void
fetchSFACollectionAndPrint(NSString *client)
{
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();

    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] getSFACollectionForCollection:client reply:^(NSData *data, NSError *error) {
        if (data == nil && error) {
            nsprintf(@"Supd reports failure: %@", error);
        }
        printSFACollectionData(data);
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
    
}

static void
storeSFACollectionInDaemon(NSString *client, NSData *_Nullable data)
{
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    NSXPCConnection* connection = getConnection();

    [[connection remoteObjectProxyWithErrorHandler:^(NSError * _Nonnull error) {
        nsprintf(@"Could not communicate with supd: %@", error);
        dispatch_semaphore_signal(sema);
    }] setSFACollection:data forTopic:client reply:^(NSError *error) {
        if (error) {
            nsprintf(@"Supd reports failure: %@", error);
        }
        dispatch_semaphore_signal(sema);
    }];

    if(dispatch_semaphore_wait(sema, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC * 20)) != 0) {
        printf("\n\nError: timed out waiting for response from supd\n");
    }
    [connection invalidate];
}


static int forceUpload = 0;
static int getJSON = 0;
static int getChunkedJSON = 0;
static int getSysdiagnose = 0;
static int getInfo = 0;
static int setOldUploadDate = 0;
static int sfaCollection = 0;
static int printSFACollection = 0;
static int storeSFACollection = 0;
static int getSFACollection = 0;
static char *topicName = NULL;
static char *inputJsonFile = NULL;
static char *binarySFAFile = NULL;

int main(int argc, char **argv)
{
    static struct argument options[] = {
        { .shortname='t', .longname="topicName", .argument=&topicName, .description="Operate on a non-default topic"},
        { .shortname='j', .longname="jsonFile", .argument=&inputJsonFile, .description="Input JSON file"},
        { .shortname='s', .longname="binarySFAFile", .argument=&binarySFAFile, .description="Binary SFACollection file"},
        { .command="sysdiagnose", .flag=&getSysdiagnose, .flagval=true, .description="Retrieve the current sysdiagnose dump for security analytics"},
        { .command="get", .flag=&getJSON, .flagval=true, .description="Get the JSON blob we would upload to the server if an upload were due"},
        { .command="getChunked", .flag=&getChunkedJSON, .flagval=true, .description="Chunk the JSON blob"},
        { .command="upload", .flag=&forceUpload, .flagval=true, .description="Force an upload of analytics data to server (ignoring privacy settings)"},
        { .command="info", .flag=&getInfo, .flagval=true, .description="Request info about clients"},
        { .command="set-old-upload-date", .flag=&setOldUploadDate, .flagval=true, .description="Clear last upload date"},
        { .command="encode-sfa-collection", .flag=&sfaCollection, .flagval=true, .description="Encode SFA Collection"},
        { .command="print-sfa-collection", .flag=&printSFACollection, .flagval=true, .description="Encode SFA Collection"},
        { .command="store-sfa-collection", .flag=&storeSFACollection, .flagval=true, .description="Store SFA Collection"},
        { .command="get-sfa-collection", .flag=&getSFACollection, .flagval=true, .description="Get SFA Collection"},

        {}  // Need this!
    };

    static struct arguments args = {
        .programname="supdctl",
        .description="Control and report on security analytics",
        .arguments = options,
    };

    if(!options_parse(argc, argv, &args)) {
        printf("\n");
        print_usage(&args);
        return -1;
    }

    if (!SecIsInternalRelease()) {
        abort();
    }

    @autoreleasepool {
        if (forceUpload) {
            forceUploadAnalytics();
        } else if (getJSON) {
            createLoggingJSON(topicName);
        } else if (getChunkedJSON) {
            createChunkedLoggingJSON(topicName);
        } else if (getSysdiagnose) {
            getSysdiagnoseDump();
        } else if (getInfo) {
            getInfoDump();
        } else if (setOldUploadDate) {
            forceOldUploadDate();
        } else if (sfaCollection) {
            if (inputJsonFile == NULL || binarySFAFile == NULL) {
                print_usage(&args);
                return -1;
            }
            NSString *str = [NSString stringWithUTF8String:inputJsonFile];
            encodeSFACollection(str, @(binarySFAFile));
        } else if (getSFACollection) {
            if (topicName == nil) {
                print_usage(&args);
                return -1;
            }
            fetchSFACollectionAndPrint(@(topicName));
        } else if (storeSFACollection) {
            if (topicName == nil || binarySFAFile == nil) {
                print_usage(&args);
                return -1;
            }
            NSData *data = [NSData dataWithContentsOfFile:@(binarySFAFile)];
            if (data == nil) {
                nsprintf(@"Can't read file %s", binarySFAFile);
                return -1;
            }
            storeSFACollectionInDaemon(@(topicName), data);
        } else if (printSFACollection) {
            if (binarySFAFile == NULL) {
                print_usage(&args);
                return -1;
            }
            NSData *data = [NSData dataWithContentsOfFile:@(binarySFAFile)];
            if (data == nil) {
                nsprintf(@"Can't read file %s", binarySFAFile);
                return -1;
            }
            printSFACollectionData(data);
        } else {
            print_usage(&args);
            return -1;
        }
    }
    return 0;
}

