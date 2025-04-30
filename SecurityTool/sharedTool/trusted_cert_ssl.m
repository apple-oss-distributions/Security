/*
 * Copyright (c) 2019 Apple Inc. All Rights Reserved.
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
 * trusted_cert_ssl.m
 */


#import "trusted_cert_ssl.h"
#include <Foundation/Foundation.h>
#include <CoreServices/CoreServices.h>
#include <Security/Security.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !TARGET_OS_BRIDGE
#include <Network/Network.h>
#include <nw/private.h>
#endif

#pragma clang diagnostic ignored "-Wdeprecated-declarations"


#if !TARGET_OS_BRIDGE
@interface TLSConnection : NSObject

@property NSURL *url;
@property NSError *error;
@property SecTrustRef trust;
@property BOOL finished;
@property BOOL udp; // default is NO (use tcp)
@property int verbose;
@property dispatch_queue_t queue;
@property nw_connection_t connection;

- (id)initWithURLString:(const char *)urlstr verbose:(int)level;
- (void)dealloc;
- (nw_connection_t)createConnection;
- (void)startConnection;
- (void)waitForConnection;
- (NSError*)error;
- (SecTrustRef)trust;

+ (BOOL)isNetworkURL:(const char *)urlstr;

@end
#endif // !TARGET_OS_BRIDGE

#define ANSI_RED     "\x1b[31m"
#define ANSI_GREEN   "\x1b[32m"
#define ANSI_YELLOW  "\x1b[33m"
#define ANSI_BLUE    "\x1b[34m"
#define ANSI_MAGENTA "\x1b[35m"
#define ANSI_CYAN    "\x1b[36m"
#define ANSI_RESET   "\x1b[0m"

#if OBJC_ARC_DISABLED
#define NW_RETAIN(obj) nw_retain(obj)
#define NW_RELEASE(obj) nw_release(obj)
#define SEC_RELEASE(obj) sec_release(obj)
#define OBJ_RELEASE(obj) [obj release]
#define SUPER_DEALLOC [super dealloc]
#else
#define NW_RETAIN(obj)
#define NW_RELEASE(obj)
#define SEC_RELEASE(obj)
#define OBJ_RELEASE(obj)
#define SUPER_DEALLOC
#endif

#if !TARGET_OS_BRIDGE
@implementation TLSConnection

- (id)initWithURLString:(const char *)urlstr verbose:(int)level
{
    if ((self = [super init])) {
        _url = [[NSURL alloc] initWithString:[NSString stringWithFormat:@"%s", urlstr]];
        _udp = NO;
        _finished = NO;
        _verbose = level;
        _error = nil;
        _trust = NULL;
        _queue = dispatch_get_main_queue();
        _connection = [self createConnection];
    }

    return self;
}

- (void)dealloc
{
    if (_connection) {
        NW_RELEASE(_connection);
        _connection = NULL;
    }
    if (_error) {
        OBJ_RELEASE(_error);
        _error = nil;
    }
    if (_url) {
        OBJ_RELEASE(_url);
        _url = nil;
    }
    if (_trust) {
        CFRelease(_trust);
        _trust = NULL;
    }
    SUPER_DEALLOC;
}

- (nw_connection_t)createConnection
{
    const char *host = [[self.url host] UTF8String];
    const char *port = [[[self.url port] stringValue] UTF8String];
    if (!host) {
        if (_verbose > 0) { fprintf(stderr, "Unable to continue without a hostname (is URL valid?)\n"); }
        self.finished = YES;
        return NULL;
    }
    nw_endpoint_t endpoint = nw_endpoint_create_host(host, (port) ? port : "443");
    nw_parameters_configure_protocol_block_t configure_tls = ^(nw_protocol_options_t _Nonnull options) {
        sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(options);
        sec_protocol_options_set_verify_block(sec_options, ^(
            sec_protocol_metadata_t _Nonnull metadata, sec_trust_t _Nonnull trust_ref, sec_protocol_verify_complete_t _Nonnull complete) {
            SecTrustRef trust = sec_trust_copy_ref(trust_ref);
            if (trust) {
                CFRetain(trust);
                if (self.trust) { CFRelease(self.trust); }
                self.trust = trust;
            }
            CFErrorRef error = NULL;
            BOOL allow = SecTrustEvaluateWithError(trust, &error);
            if (error) {
                if (self.error) { OBJ_RELEASE(self.error); }
                self.error = (__bridge NSError *)error;
            }
            complete(allow);
        }, self.queue);
    };
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(configure_tls, NW_PARAMETERS_DEFAULT_CONFIGURATION);
    nw_parameters_set_indefinite(parameters, false); // so we don't enter the 'waiting' state on TLS failure
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    NW_RELEASE(endpoint);
    NW_RELEASE(parameters);
    return connection;
}

- (void)startConnection
{
    nw_connection_set_queue(_connection, _queue);
    NW_RETAIN(_connection); // Hold a reference until cancelled

    nw_connection_set_state_changed_handler(_connection, ^(nw_connection_state_t state, nw_error_t error) {
        nw_endpoint_t remote = nw_connection_copy_endpoint(self.connection);
        errno = error ? nw_error_get_error_code(error) : 0;
        const char *protocol = self.udp ? "udp" : "tcp";
        const char *host = nw_endpoint_get_hostname(remote);
        uint16_t port = nw_endpoint_get_port(remote);
        // note: this code does not handle or expect nw_connection_state_waiting,
        // since the connection parameters specified a definite connection.
        if (state == nw_connection_state_failed) {
            if (self.verbose > 0) {
                fprintf(stderr, "connection to %s port %u (%s) failed\n", host, port, protocol);
            }
            // Cancel the connection, so we go to nw_connection_state_cancelled
            nw_connection_cancel(self.connection);

        } else if (state == nw_connection_state_ready) {
            if (self.verbose > 0) {
                fprintf(stderr, "connection to %s port %u (%s) opened\n", host, port, protocol);
            }
            // Once we get the SecTrustRef, we can cancel the connection
            nw_connection_cancel(self.connection);

        } else if (state == nw_connection_state_cancelled) {
            if (self.verbose > 0) {
                fprintf(stderr, "connection to %s port %u (%s) closed\n", host, port, protocol);
            }
            nw_connection_cancel(self.connection); // cancel to be safe (should be a no-op)
            NW_RELEASE(_connection); // release the reference and set flag to exit loop
            self.finished = YES;
        }
        NW_RELEASE(remote);
    });

    nw_connection_start(_connection);
}

- (void)waitForConnection
{
    while (_finished == NO) {
        NSDate *cycleTime = [NSDate dateWithTimeIntervalSinceNow:0.1];
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:cycleTime];
    }
}

+ (BOOL)isNetworkURL:(const char *)urlstr
{
    if (urlstr) {
        NSArray *schemes = @[@"https",@"ldaps"];
        NSURL *url = [NSURL URLWithString:[NSString stringWithUTF8String:urlstr]];
        if (url && [schemes containsObject:[url scheme]]) {
            return YES;
        }
    }
    return NO;
}

@end
#endif // !TARGET_OS_BRIDGE

static NSString *errorStringForKey(NSString *key)
{
    NSString *errstr = nil;
    // %%% note: these dictionary keys currently do not have exported constants
    if (![key length] || [key isEqualToString:@"StatusCodes"]) {
        return errstr; // skip empty and legacy numeric errors
    } else if ([key isEqualToString:@"SSLHostname"]) {
        errstr = @"Host name not found in Subject Alternative Name extension";
    } else if ([key isEqualToString:@"TemporalValidity"]) {
        errstr = @"Certificate has expired, or is not yet valid (check date)";
    } else if ([key isEqualToString:@"KeySize"]) {
        errstr = @"Certificate uses a key size which is considered too weak";
    } else if ([key isEqualToString:@"SignatureHashAlgorithms"]) {
        errstr = @"Certificate uses a signing algorithm which is considered too weak";
    } else if ([key isEqualToString:@"KeyUsage"]) {
        errstr = @"The Key Usage extension does not permit this use for the certificate";
    } else if ([key isEqualToString:@"ExtendedKeyUsage"]) {
        errstr = @"The Extended Key Usage extension does not permit this use for the certificate";
    } else if ([key isEqualToString:@"Revocation"]) {
        errstr = @"Certificate has been revoked and cannot be used";
    } else if ([key isEqualToString:@"BlackListedLeaf"]) {
        errstr = @"Certificate has been blocked and cannot be used";
    } else if ([key isEqualToString:@"AnchorTrusted"]) {
        errstr = @"The root of the certificate chain is not trusted";
    } else if ([key isEqualToString:@"MissingIntermediate"]) {
        errstr = @"Unable to find next certificate in the chain";
    } else if ([key isEqualToString:@"NonEmptySubject"]) {
        errstr = @"Certificate has no subject, and SAN is missing or not marked critical";
    } else if ([key isEqualToString:@"BasicCertificateProcessing"]) {
        errstr = @"Certificate not standards compliant (RFC 5280|CABF Baseline Requirements)";
    } else if ([key isEqualToString:@"NameConstraints"]) {
        errstr = @"Certificate violates name constraints placed on issuing CA";
    } else if ([key isEqualToString:@"PolicyConstraints"]) {
        errstr = @"Certificate violates policy constraints placed on issuing CA";
    } else if ([key isEqualToString:@"CTRequired"]) {
        errstr = @"Certificate Transparency validation is required but missing";
    } else if ([key isEqualToString:@"ValidityPeriodMaximums"]) {
        errstr = @"Certificate exceeds maximum allowable validity period (normally 825 days)";
    } else if ([key isEqualToString:@"ServerAuthEKU"]) {
        errstr = @"The Extended Key Usage extension does not permit server authentication";
    } else if ([key isEqualToString:@"UnparseableExtension"]) {
        errstr = @"Unable to parse a standard extension (corrupt or invalid format detected)";
    }

    if (errstr) {
        errstr = [NSString stringWithFormat:@"%@ [%@]", errstr, key];
    } else {
        errstr = [NSString stringWithFormat:@"[%@]", key];
    }
    return errstr;
}

void printErrorDetails(SecTrustRef trust)
{
    CFDictionaryRef result = SecTrustCopyResult(trust);
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CFArrayRef properties = SecTrustCopyProperties(trust);
#pragma clang diagnostic pop
    NSArray *props = (__bridge NSArray *)properties;
    NSArray *details = [(__bridge NSDictionary *)result objectForKey:@"TrustResultDetails"];
    if (!props || !details) {
        if (result) { CFRelease(result); }
        if (properties) { CFRelease(properties); }
        return;
    }
    // Preflight to see if there are any errors to display
    CFIndex errorCount = 0, chainLength = [details count];
    for (CFIndex chainIndex = 0; chainIndex < chainLength; chainIndex++) {
        NSDictionary *certDetails = (NSDictionary *)[details objectAtIndex:chainIndex];
        errorCount += [certDetails count];
    }
    if (!errorCount) {
        if (result) { CFRelease(result); }
        if (properties) { CFRelease(properties); }
        return;
    }

    // Display per-certificate errors
    fprintf(stdout, "---\nCertificate errors\n");
    for (CFIndex chainIndex = 0; chainIndex < chainLength; chainIndex++) {
        NSDictionary *certProps = (NSDictionary *)[props objectAtIndex:chainIndex];
        NSString *certTitle = (NSString *)[certProps objectForKey:(__bridge NSString*)kSecPropertyTypeTitle];
        fprintf(stdout, " %ld: %s\n", (long)chainIndex, [certTitle UTF8String]);
        NSDictionary *certDetails = (NSDictionary *)[details objectAtIndex:chainIndex];
        NSEnumerator *keyEnumerator = [certDetails keyEnumerator];
        NSString *key;
        while ((key = (NSString*)[keyEnumerator nextObject])) {
            NSString *str = errorStringForKey(key);
            if (!str) { continue; }
            fprintf(stdout, ANSI_RED "    %s" ANSI_RESET "\n", [str UTF8String]);
        }
    }
    fflush(stdout);

    CFRelease(result);
    CFRelease(properties);
}

void printExtendedResults(SecTrustRef trust)
{
    CFDictionaryRef trustResults = SecTrustCopyResult(trust);
    if (!trustResults) { return; }
    fprintf(stdout, "---\n");

    NSDictionary *results = (__bridge NSDictionary *)trustResults;
    NSString *orgName = [results objectForKey:(NSString *)kSecTrustOrganizationName];
    CFBooleanRef isEV = (__bridge CFBooleanRef)[results objectForKey:(NSString *)kSecTrustExtendedValidation];
    if (isEV == kCFBooleanTrue) {
        fprintf(stdout, "Extended Validation (EV) confirmed for \"" ANSI_GREEN "%s" ANSI_RESET "\"\n", [orgName UTF8String]);
    } else {
        fprintf(stdout, "No extended validation result found\n");
    }
    CFBooleanRef isCT = (__bridge CFBooleanRef)[results objectForKey:(NSString *)kSecTrustCertificateTransparency];
    if (isCT == kCFBooleanTrue) {
        fprintf(stdout, "Certificate Transparency (CT) status: " ANSI_GREEN "verified" ANSI_RESET "\n");
    } else {
        fprintf(stdout, "Certificate Transparency (CT) status: " ANSI_RED "not verified" ANSI_RESET "\n");
        fprintf(stdout, "Unable to find at least 2 signed certificate timestamps (SCTs) from approved logs\n");
    }
    fflush(stdout);
    CFRelease(trustResults);
}

int evaluate_ssl(const char *urlstr, int verbose, SecTrustRef * CF_RETURNS_RETAINED trustRef)
{
#if TARGET_OS_BRIDGE
    // need to make sure we can use/link network frameworks on bridgeOS;
    // for now, url evaluation is unsupported on that platform.
    if (trustRef) { *trustRef = NULL; }
    fprintf(stderr, "url evaluation not supported on bridgeOS\n");
    return 2;
#else
    @autoreleasepool {
        if (trustRef) {
            *trustRef = NULL;
        }
        if (![TLSConnection isNetworkURL:urlstr]) {
            return 2;
        }
        TLSConnection *tls = [[TLSConnection alloc] initWithURLString:urlstr verbose:verbose];
        [tls startConnection];
        [tls waitForConnection];

        NSError *error = [tls error];
        if (verbose && error) {
            fprintf(stderr, "NSError: { ");
            CFShow((__bridge CFErrorRef)error);
            fprintf(stderr,"}\n");
        }

        SecTrustRef trust = [tls trust];
        if (trustRef && trust) {
            CFRetain(trust);
            *trustRef = trust;
        }
        OBJ_RELEASE(tls);
        tls = nil;
    }
    return 0;
#endif
}
