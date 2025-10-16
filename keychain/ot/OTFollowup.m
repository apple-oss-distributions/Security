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
 */

#if OCTAGON

#import "OTFollowup.h"

#if __has_include(<CoreFollowUp/CoreFollowUp.h>) && !TARGET_OS_SIMULATOR
#import <CoreFollowUp/CoreFollowUp.h>
#define HAVE_COREFOLLOW_UP 1
#endif

#import <CoreCDP/CDPFollowUpController.h>
#import <CoreCDP/CDPFollowUpContext.h>
#import "keychain/ot/OTConstants.h"
#import <Accounts/Accounts.h>
#import <Accounts/Accounts_Private.h>
#import <AppleAccount/ACAccount+AppleAccount.h>
#include "utilities/debugging.h"
#import "OTFollowup.h"

static NSString * const kOTFollowupEventCompleteKey = @"OTFollowupContextType";

NSString* OTFollowupContextTypeToString(OTFollowupContextType contextType)
{
    switch(contextType) {
        case OTFollowupContextTypeNone:
            return @"none";
#if OCTAGON_PLATFORM_SUPPORTS_RK_CFU
        case OTFollowupContextTypeRecoveryKeyRepair:
            return @"recovery key";
#endif
        case OTFollowupContextTypeStateRepair:
            return @"repair";
        case OTFollowupContextTypeConfirmExistingSecret:
            return @"confirm existing secret";
        case OTFollowupContextTypeSecureTerms:
            return @"secure terms";
        case OTFollowupContextTypeOfflinePasscodeChange:
            return @"offline passcode change";
    }
}

@interface OTFollowup()
@property id<OctagonFollowUpControllerProtocol> cdpd;
@property NSTimeInterval previousFollowupEnd;
@property NSTimeInterval followupStart;
@property NSTimeInterval followupEnd;
@property NSMutableSet<NSString*>* postedCFUTypes;
@end

@implementation OTFollowup : NSObject

- (id)initWithFollowupController:(id<OctagonFollowUpControllerProtocol>)cdpFollowupController
{
    if (self = [super init]) {
        self.cdpd = cdpFollowupController;

        _postedCFUTypes = [NSMutableSet set];
    }
    return self;
}

- (CDPFollowUpContext *)createCDPFollowupContext:(OTFollowupContextType)contextType
{
    switch (contextType) {
        case OTFollowupContextTypeStateRepair: {
            return [CDPFollowUpContext contextForStateRepair];
        }
#if OCTAGON_PLATFORM_SUPPORTS_RK_CFU
        case OTFollowupContextTypeRecoveryKeyRepair: {
            return [CDPFollowUpContext contextForRecoveryKeyRepair];
        }
#endif
        case OTFollowupContextTypeConfirmExistingSecret: {
            return [CDPFollowUpContext contextForConfirmExistingSecret];
        }
        case OTFollowupContextTypeSecureTerms: {
            return [CDPFollowUpContext contextForSecureTerms];
        }
        case OTFollowupContextTypeOfflinePasscodeChange: {
            return [CDPFollowUpContext contextForOfflinePasscodeChange];
        }
        default: {
            return nil;
        }
    }
}

- (BOOL)postFollowUp:(OTFollowupContextType)contextType
       activeAccount:(TPSpecificUser*)activeAccount
               error:(NSError **)error
{
    CDPFollowUpContext *context = [self createCDPFollowupContext:contextType];
    if (OctagonSupportsPersonaMultiuser()) {
        secnotice("followup", "Setting altdsid (%@) on context for persona (%@)", activeAccount.altDSID, activeAccount.personaUniqueString);
        [context setAltDSID:activeAccount.altDSID];
    }
    if (!context) {
        return NO;
    }

    NSError *followupError = nil;

    secnotice("followup", "Posting a follow up (for Octagon) of type %@", OTFollowupContextTypeToString(contextType));
    BOOL result = [self.cdpd postFollowUpWithContext:context error:&followupError];

    if(result) {
        [self.postedCFUTypes addObject:OTFollowupContextTypeToString(contextType)];
    } else {
        if (error) {
            *error = followupError;
        }
    }

    return result;
}

- (BOOL)clearFollowUp:(OTFollowupContextType)contextType
        activeAccount:(TPSpecificUser*)activeAccount
                error:(NSError **)error
{
    // Note(caw): we don't track metrics for clearing CFU prompts.
    CDPFollowUpContext *context = [self createCDPFollowupContext:contextType];
    if (OctagonSupportsPersonaMultiuser()) {
        secnotice("followup", "Setting altdsid (%@) on context for persona (%@)", activeAccount.altDSID, activeAccount.personaUniqueString);
        [context setAltDSID:activeAccount.altDSID];
    }
    if (!context) {
        return NO;
    }

    secnotice("followup", "Clearing follow ups (for Octagon) of type %@", OTFollowupContextTypeToString(contextType));
    BOOL result = [self.cdpd clearFollowUpWithContext:context error:error];
    if(result) {
        [self.postedCFUTypes removeObject:OTFollowupContextTypeToString(contextType)];
    }

    return result;
}

- (BOOL)clearAllRepairFollowUps:(TPSpecificUser*)activeAccount
                          error:(NSError **)error
{
    BOOL success = YES;

    success &= [self clearFollowUp:OTFollowupContextTypeConfirmExistingSecret activeAccount:activeAccount error:error];
    success &= [self clearFollowUp:OTFollowupContextTypeOfflinePasscodeChange activeAccount:activeAccount error:error];
    success &= [self clearFollowUp:OTFollowupContextTypeSecureTerms           activeAccount:activeAccount error:error];

    return success;
}

- (NSDictionary *_Nullable)sysdiagnoseStatus
{
    NSMutableDictionary *pendingCFUs = nil;

#if HAVE_COREFOLLOW_UP
    if ([FLFollowUpController class]) {
        NSError *error = nil;
        pendingCFUs = [NSMutableDictionary dictionary];

        FLFollowUpController *followUpController = [[FLFollowUpController alloc] initWithClientIdentifier:nil];
        NSArray <FLFollowUpItem*>* followUps = [followUpController pendingFollowUpItems:&error];
        if (error) {
            secnotice("octagon", "Fetching pending follow ups failed with: %@", error);
            pendingCFUs[@"error"] = [error description];
        }
        for (FLFollowUpItem *followUp in followUps) {
            NSDate *creationDate = followUp.notification.creationDate;

            if(creationDate) {
                NSISO8601DateFormatter *formatter = [[NSISO8601DateFormatter alloc] init];
                pendingCFUs[followUp.uniqueIdentifier] = [formatter stringForObjectValue:creationDate];
            } else {
                pendingCFUs[followUp.uniqueIdentifier] = @"creation-date-missing";
            }
        }
    }
#endif
    return pendingCFUs;
}

- (NSDictionary<NSString*,NSNumber *> *)sfaStatus {
    NSMutableDictionary<NSString*, NSNumber*>* values = [NSMutableDictionary dictionary];
#if HAVE_COREFOLLOW_UP
    if ([FLFollowUpController class]) {
        NSError *error = nil;

        FLFollowUpController *followUpController = [[FLFollowUpController alloc] initWithClientIdentifier:nil];
        NSArray <FLFollowUpItem*>* followUps = [followUpController pendingFollowUpItems:&error];
        if (error) {
            secnotice("octagon", "Fetching pending follow ups failed with: %@", error);
        }
        for (FLFollowUpItem *followUp in followUps) {
            NSInteger created = 10000;

            NSDate *creationDate = followUp.notification.creationDate;
            if (creationDate) {
                created = [CKKSAnalytics fuzzyDaysSinceDate:creationDate];
            }
            NSString *key = [NSString stringWithFormat:@"OACFU-%@", followUp.uniqueIdentifier];
            values[key] = @(created);
        }

        secnotice("octagon", "Analytics CFUs are %@", values);
    }
#endif
    return values;
}

@end

@implementation OTFollowup (Testing)
- (BOOL)hasPosted:(OTFollowupContextType)contextType
{
    return [self.postedCFUTypes containsObject:OTFollowupContextTypeToString(contextType)];
}

- (void)clearAllPostedFlags
{
    [self.postedCFUTypes removeAllObjects];
}
@end

#endif // OCTAGON
