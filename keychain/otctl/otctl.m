//
//  Security
//

#import <TargetConditionals.h>
#import <Foundation/Foundation.h>
#import <Security/SecInternalReleasePriv.h>
#import <Security/Security.h>
#import <err.h>
#import <OctagonTrust/OctagonTrust.h>

#import "keychain/otctl/OTControlCLI.h"
#import "keychain/ot/OTDefines.h"
#import "keychain/otctl/EscrowRequestCLI.h"
#import "keychain/escrowrequest/Framework/SecEscrowRequest.h"
#include "lib/SecArgParse.h"
#include "utilities/debugging.h"

#if TARGET_OS_WATCH
#import "keychain/otpaird/OTPairingClient.h"
#endif /* TARGET_OS_WATCH */

#import <AppleFeatures/AppleFeatures.h>

static int start = false;
static int signIn = false;
static int signOut = false;
static int resetoctagon = false;
static int resetProtectedData = false;
static int userControllableViewsSyncStatus = false;

static int fetchAllBottles = false;
static int recover = false;
static int depart = false;

static int status = false;

static int er_trigger = false;
static int er_status = false;
static int er_reset = false;
static int er_store = false;
static int ckks_policy_flag = false;

static int ttr_flag = false;

static int fetch_escrow_records = false;
static int fetch_all_escrow_records = false;

static int recoverRecord = false;
static int recoverSilentRecord = false;

static int resetAccountCDPContent = false;

static int createCustodianRecoveryKey = false;
static int joinWithCustodianRecoveryKey = false;
static int preflightJoinWithCustodianRecoveryKey = false;
static int removeCustodianRecoveryKey = false;

static int setRecoveryKey = false;
static int removeRecoveryKey = false;

static int createInheritanceKey = false;
static int generateInheritanceKey = false;
static int storeInheritanceKey = false;
static int joinWithInheritanceKey = false;
static int preflightJoinWithInheritanceKey = false;
static int removeInheritanceKey = false;

static int fetchAccountSettings = false;
static int fetchAccountWideSettings = false;

static int enableWalrus = false;
static int disableWalrus = false;

static int enableWebAccess = false;
static int disableWebAccess = false;

static int health = false;
static int tlkRecoverability = false;
static int machineIDOverride = false;

#if TARGET_OS_WATCH
static int pairme = false;
#endif /* TARGET_OS_WATCH */

static char* bottleIDArg = NULL;
static char* contextNameArg = NULL;
static char* secretArg = NULL;
static char* skipRateLimitingCheckArg = NULL;
static char* recordID = NULL;

static char* overrideForAccountScriptArg = NULL;
static char* overrideEscrowCacheArg = NULL;

static char* machineIDArg = NULL;

static int argEnable = false;
static int argPause = false;

static int json = false;

static int notifyIdMS = false;

static int printAccountMetadata = false;

static int forceFetch = false;

static char* altDSIDArg = NULL;
static char* containerStr = NULL;
static char* radarNumber = NULL;
static char* appleIDArg = NULL;
static char* dsidArg = NULL;
static char* wrappingKeyArg = NULL;
static char* wrappedKeyArg = NULL;
static char* custodianUUIDArg = NULL;
static char* inheritanceUUIDArg = NULL;
static char* timeoutInS = NULL;

static char* idmsTargetContext = NULL;
static char* idmsCuttlefishPassword = NULL;


int main(int argc, char** argv)
{
    static struct argument options[] = {
        {.shortname = 's', .longname = "secret", .argument = &secretArg, .description = "escrow secret"},
        {.shortname = 'e', .longname = "bottleID", .argument = &bottleIDArg, .description = "bottle record id"},
        {.shortname = 'r', .longname = "skipRateLimiting", .argument = &skipRateLimitingCheckArg, .description = " enter values YES or NO, option defaults to NO, This gives you the opportunity to skip the rate limiting check when performing the cuttlefish health check"},
        {.shortname = 'j', .longname = "json", .flag = &json, .flagval = true, .description = "Output in JSON"},
        {.shortname = 'i', .longname = "recordID", .argument = &recordID, .flagval = true, .description = "recordID"},

        {.shortname = 'o', .longname = "overrideForAccountScript", .argument = &overrideForAccountScriptArg, .description = " enter values YES or NO, option defaults to NO, This flag is only meant for the setup account for icloud cdp signin script"},
        {.shortname = 'c', .longname = "overrideEscrowCache", .argument = &overrideEscrowCacheArg, .description = " enter values YES or NO, option defaults to NO, include this if you want to force an escrow record fetch from cuttlefish for the freshest of escrow records"},

        {.shortname = 'E', .longname = "enable", .flag = &argEnable, .flagval = true, .description = "Enable something (pair with a modification command)"},
        {.shortname = 'P', .longname = "pause", .flag = &argPause, .flagval = true, .description = "Pause something (pair with a modification command)"},
	{.longname = "notifyIdMS", .flag = &notifyIdMS, .flagval = true, .description = "Notify IdMS on reset", .internal_only = true},
        {.longname = "forceFetch", .flag = &forceFetch, .flagval = true, .description = "Force fetch from cuttlefish"},

        {.shortname = 'a', .longname = "machineID", .argument = &machineIDArg, .description = "machineID override"},

        {.longname = "altDSID", .argument = &altDSIDArg, .description = "altDSID (for sign-in/out)"},
        {.longname = "entropy", .argument = &secretArg, .description = "escrowed entropy in JSON"},

        {.longname = "appleID", .argument = &appleIDArg, .description = "AppleID"},
        {.longname = "dsid", .argument = &dsidArg, .description = "DSID", .internal_only = true},

        {.longname = "container", .argument = &containerStr, .description = "CloudKit container name"},
        {.longname = "context", .argument = &contextNameArg, .description = "Context name"},
        {.longname = "radar", .argument = &radarNumber, .description = "Radar number"},

        {.longname = "wrapping-key", .argument = &wrappingKeyArg, .description = "Wrapping key (for joinWithCustodianRecoveryKey)", .internal_only = true},
        {.longname = "wrapped-key", .argument = &wrappedKeyArg, .description = "Wrapped key (for joinWithCustodianRecoveryKey)", .internal_only = true},
        {.longname = "custodianUUID", .argument = &custodianUUIDArg, .description = "UUID for joinWithCustodianRecoveryKey", .internal_only = true},
        {.longname = "inheritanceUUID", .argument = &inheritanceUUIDArg, .description = "UUID for joinWithInheritanceKey", .internal_only = true},
        {.longname = "timeout", .argument = &timeoutInS, .description = "timeout for command (in s)"},

        {.longname = "idms-target-context", .argument = &idmsTargetContext, .description = "idmsTargetContext", .internal_only = true},
        {.longname = "idms-cuttlefish-password", .argument = &idmsCuttlefishPassword, .description = "idmsCuttlefishPassword", .internal_only = true},

        {.command = "start", .flag = &start, .flagval = true, .description = "Start Octagon state machine", .internal_only = true},
        {.command = "sign-in", .flag = &signIn, .flagval = true, .description = "Inform Cuttlefish container of sign in", .internal_only = true},
        {.command = "sign-out", .flag = &signOut, .flagval = true, .description = "Inform Cuttlefish container of sign out", .internal_only = true},
        {.command = "status", .flag = &status, .flagval = true, .description = "Report Octagon status"},

        {.command = "resetoctagon", .flag = &resetoctagon, .flagval = true, .description = "Reset and establish new Octagon trust"},
        {.command = "resetProtectedData", .flag = &resetProtectedData, .flagval = true, .description = "Reset ProtectedData", .internal_only = true},

        {.command = "user-controllable-views", .flag = &userControllableViewsSyncStatus, .flagval = true, .description = "Modify or view user-controllable views status (If one of --enable or --pause is passed, will modify status)", .internal_only = true},

        {.command = "allBottles", .flag = &fetchAllBottles, .flagval = true, .description = "Fetch all viable bottles"},
        {.command = "recover", .flag = &recover, .flagval = true, .description = "Recover using this bottle"},
        {.command = "depart", .flag = &depart, .flagval = true, .description = "Depart from Octagon Trust"},

        {.command = "er-trigger", .flag = &er_trigger, .flagval = true, .description = "Trigger an Escrow Request request", .internal_only = true},
        {.command = "er-status", .flag = &er_status, .flagval = true, .description = "Report status on any pending Escrow Request requests"},
        {.command = "er-reset", .flag = &er_reset, .flagval = true, .description = "Delete all Escrow Request requests"},
        {.command = "er-store", .flag = &er_store, .flagval = true, .description = "Store any pending Escrow Request prerecords"},

        {.command = "health", .flag = &health, .flagval = true, .description = "Check Octagon Health status"},
        {.command = "ckks-policy", .flag = &ckks_policy_flag, .flagval = true, .description = "Trigger a refetch of the CKKS policy"},

        {.command = "taptoradar", .flag = &ttr_flag, .flagval = true, .description = "Trigger a TapToRadar"},

        {.command = "fetchEscrowRecords", .flag = &fetch_escrow_records, .flagval = true, .description = "Fetch Escrow Records"},
        {.command = "fetchAllEscrowRecords", .flag = &fetch_all_escrow_records, .flagval = true, .description = "Fetch All Escrow Records"},

        {.command = "recover-record", .flag = &recoverRecord, .flagval = true, .description = "Recover record"},
        {.command = "recover-record-silent", .flag = &recoverSilentRecord, .flagval = true, .description = "Silent record recovery"},

        {.command = "reset-account-cdp-contents", .flag = &resetAccountCDPContent, .flagval = true, .description = "Reset an account's CDP contents (escrow records, kvs data, cuttlefish)"},

        {.command = "create-custodian-recovery-key", .flag = &createCustodianRecoveryKey, .flagval = true, .description = "Create a custodian recovery key", .internal_only = true},
        {.command = "join-with-custodian-recovery-key", .flag = &joinWithCustodianRecoveryKey, .flagval = true, .description = "Join with a custodian recovery key", .internal_only = true},
        {.command = "preflight-join-with-custodian-recovery-key", .flag = &preflightJoinWithCustodianRecoveryKey, .flagval = true, .description = "Preflight join with a custodian recovery key", .internal_only = true},
        {.command = "remove-custodian-recovery-key", .flag = &removeCustodianRecoveryKey, .flagval = true, .description = "Remove a custodian recovery key", .internal_only = true},
        {.command = "create-inheritance-key", .flag = &createInheritanceKey, .flagval = true, .description = "Create an inheritance key", .internal_only = true},
        {.command = "generate-inheritance-key", .flag = &generateInheritanceKey, .flagval = true, .description = "Generate an inheritance key", .internal_only = true},
        {.command = "store-inheritance-key", .flag = &storeInheritanceKey, .flagval = true, .description = "Store an inheritance key", .internal_only = true},
        {.command = "join-with-inheritance-key", .flag = &joinWithInheritanceKey, .flagval = true, .description = "Join with an inheritance key", .internal_only = true},
        {.command = "preflight-join-with-inheritance-key", .flag = &preflightJoinWithInheritanceKey, .flagval = true, .description = "Preflight join with an inheritance key", .internal_only = true},
        {.command = "remove-inheritance-key", .flag = &removeInheritanceKey, .flagval = true, .description = "Remove an inheritance key", .internal_only = true},
        {.command = "tlk-recoverability", .flag = &tlkRecoverability, .flagval = true, .description = "Evaluate tlk recoverability for an account", .internal_only = true},
        {.command = "set-machine-id-override", .flag = &machineIDOverride, .flagval = true, .description = "Set machineID override"},
        {.command = "remove-recovery-key", .flag = &removeRecoveryKey, .flagval = true, .description = "Remove a recovery key", .internal_only = true},
        {.command = "set-recovery-key", .flag = &setRecoveryKey, .flagval = true, .description = "Set a recovery key", .internal_only = true},

        {.command = "enable-walrus", .flag = &enableWalrus, .flagval = true, .description = "Enable Walrus Setting", .internal_only = true},
        {.command = "disable-walrus", .flag = &disableWalrus, .flagval = true, .description = "Disable Walrus Setting", .internal_only = true},
        {.command = "enable-webaccess", .flag = &enableWebAccess, .flagval = true, .description = "Enable Web Access Setting", .internal_only = true},
        {.command = "disable-webaccess", .flag = &disableWebAccess, .flagval = true, .description = "Disable Web Access Setting", .internal_only = true},
        {.command = "fetch-account-state", .flag = &fetchAccountSettings, .flagval = true, .description = "Fetch Account Settings", .internal_only = true},
        {.command = "fetch-account-wide-state", .flag = &fetchAccountWideSettings, .flagval = true, .description = "Fetch Account Wide Settings", .internal_only = true},

#if TARGET_OS_WATCH
        {.command = "pairme", .flag = &pairme, .flagval = true, .description = "Perform pairing (watchOS only)"},
#endif /* TARGET_OS_WATCH */

        {.command = "print-account-metadata", .flag = &printAccountMetadata, .flagval = true, .description = "Print Account Metadata", .internal_only = true},

        {}};

    static struct arguments args = {
        .programname = "otctl",
        .description = "Control and report on Octagon Trust",
        .arguments = options,
    };

    if(!options_parse(argc, argv, &args)) {
        printf("\n");
        print_usage(&args);
        return 1;
    }

    @autoreleasepool {
        NSError* error = nil;

        // Use a synchronous control object
        OTControl* rpc = [OTControl controlObject:true error:&error];
        if(error || !rpc) {
            errx(1, "no OTControl failed: %s", [[error description] UTF8String]);
        }

        NSString* context = contextNameArg ? [NSString stringWithCString:contextNameArg encoding:NSUTF8StringEncoding] : OTDefaultContext;
        NSString* container = containerStr ? [NSString stringWithCString:containerStr encoding:NSUTF8StringEncoding] : OTCKContainerName;
        NSString* altDSID = altDSIDArg ? [NSString stringWithCString:altDSIDArg encoding:NSUTF8StringEncoding] : nil;
        NSString* dsid = dsidArg ? [NSString stringWithCString:dsidArg encoding:NSUTF8StringEncoding] : nil;
        NSString* appleID = appleIDArg ? [NSString stringWithCString:appleIDArg encoding:NSUTF8StringEncoding] : nil;

        NSString* skipRateLimitingCheck = skipRateLimitingCheckArg ? [NSString stringWithCString:skipRateLimitingCheckArg encoding:NSUTF8StringEncoding] : @"NO";

        NSString* wrappingKey = wrappingKeyArg ? [NSString stringWithCString:wrappingKeyArg encoding:NSUTF8StringEncoding] : nil;
        NSString* wrappedKey = wrappedKeyArg ? [NSString stringWithCString:wrappedKeyArg encoding:NSUTF8StringEncoding] : nil;
        NSString* custodianUUIDString = custodianUUIDArg ? [NSString stringWithCString:custodianUUIDArg encoding:NSUTF8StringEncoding] : nil;
        NSString* inheritanceUUIDString = inheritanceUUIDArg ? [NSString stringWithCString:inheritanceUUIDArg encoding:NSUTF8StringEncoding] : nil;
        NSTimeInterval timeout = timeoutInS ? [[NSString stringWithCString:timeoutInS encoding:NSUTF8StringEncoding] integerValue] : 600;
        NSString* idmsTargetContextString = idmsTargetContext ? [NSString stringWithCString:idmsTargetContext encoding:NSUTF8StringEncoding] : nil;
        NSString* idmsCuttlefishPasswordString = idmsCuttlefishPassword ? [NSString stringWithCString:idmsCuttlefishPassword encoding:NSUTF8StringEncoding] : nil;

        NSString* overrideForAccountScript = overrideForAccountScriptArg ? [NSString stringWithCString:overrideForAccountScriptArg encoding:NSUTF8StringEncoding] : @"NO";
        NSString* overrideEscrowCache = overrideEscrowCacheArg ? [NSString stringWithCString:overrideEscrowCacheArg encoding:NSUTF8StringEncoding] : @"NO";

        OTControlCLI* ctl = [[OTControlCLI alloc] initWithOTControl:rpc];

        OTControlArguments* arguments = [[OTControlArguments alloc] initWithContainerName:container
                                                                                contextID:context
                                                                                  altDSID:altDSID];

        NSError* escrowRequestError = nil;
        EscrowRequestCLI* escrowctl = [[EscrowRequestCLI alloc] initWithEscrowRequest:[SecEscrowRequest request:&escrowRequestError]];
        if(escrowRequestError) {
            errx(1, "SecEscrowRequest failed: %s", [[escrowRequestError description] UTF8String]);
        }
        if(resetoctagon) {
            return [ctl resetOctagon:arguments idmsTargetContext:idmsTargetContextString idmsCuttlefishPassword:idmsCuttlefishPasswordString notifyIdMS:notifyIdMS timeout:timeout];
        }
        if(resetProtectedData) {
            return [ctl resetProtectedData:arguments appleID:appleID dsid:dsid idmsTargetContext:idmsTargetContextString idmsCuttlefishPassword:idmsCuttlefishPasswordString notifyIdMS:notifyIdMS];
        }
        if(userControllableViewsSyncStatus) {
            if(argEnable && argPause) {
                print_usage(&args);
                return 1;
            }

            if(argEnable == false && argPause == false) {
                return [ctl fetchUserControllableViewsSyncStatus:arguments];
            }

            // At this point, we're sure that either argEnabled or argPause is set; so the value of argEnabled captures the user's intention
            return [ctl setUserControllableViewsSyncStatus:arguments enabled:argEnable];
        }

        if(fetchAllBottles) {
            return [ctl fetchAllBottles:arguments control:rpc];
        }
        if(recover) {
            NSString* entropyJSON = secretArg ? [NSString stringWithCString:secretArg encoding:NSUTF8StringEncoding] : nil;
            NSString* bottleID = bottleIDArg ? [NSString stringWithCString:bottleIDArg encoding:NSUTF8StringEncoding] : nil;

            if(!entropyJSON || !bottleID) {
                print_usage(&args);
                return 1;
            }

            NSData* entropy = [[NSData alloc] initWithBase64EncodedString:entropyJSON options:0];
            if(!entropy) {
                errx(1, "bad base64 string passed to --entropy");
            }

            return [ctl recoverUsingBottleID:bottleID
                                     entropy:entropy
                                   arguments:arguments
                                     control:rpc];
        }
        if(depart) {
            return [ctl depart:arguments];
        }
        if(start) {
            return [ctl startOctagonStateMachine:arguments];
        }
        if(signIn) {
            return [ctl signIn:arguments];
        }
        if(signOut) {
            return [ctl signOut:arguments];
        }

        if(status) {
            return [ctl status:arguments json:json];
        }
        if(fetch_escrow_records) {
            return [ctl fetchEscrowRecords:arguments json:json];
        }
        if(fetch_all_escrow_records) {
            return [ctl fetchAllEscrowRecords:arguments json:json];
        }
        if(machineIDOverride) {
            NSString* machineID = machineIDArg ? [NSString stringWithCString:machineIDArg encoding:NSUTF8StringEncoding] : nil;
            printf("machineID: %s\n", machineID.description.UTF8String);
                       
            return [ctl setMachineIDOverride:arguments machineID:machineID json:json];
        }
        if(recoverRecord) {
            NSString* recordIDString = recordID ? [NSString stringWithCString:recordID encoding:NSUTF8StringEncoding] : nil;
            NSString* secret = secretArg ? [NSString stringWithCString:secretArg encoding:NSUTF8StringEncoding] : nil;

            if(!recordIDString || !secret || !appleID) {
                print_usage(&args);
                return 1;
            }

            return [ctl performEscrowRecovery:arguments recordID:recordIDString appleID:appleID secret:secret overrideForAccountScript:overrideForAccountScript overrideEscrowCache:overrideEscrowCache];
        }
        if(recoverSilentRecord){
            NSString* secret = secretArg ? [NSString stringWithCString:secretArg encoding:NSUTF8StringEncoding] : nil;

            if(!secret || !appleID) {
                print_usage(&args);
                return 1;
            }

            return [ctl performSilentEscrowRecovery:arguments appleID:appleID secret:secret];
        }
        if(health) {
            BOOL skip = NO;
            if([skipRateLimitingCheck isEqualToString:@"YES"]) {
                skip = YES;
            } else {
                skip = NO;
            }
            return [ctl healthCheck:arguments skipRateLimitingCheck:skip];
        }
        if(tlkRecoverability) {
            return [ctl tlkRecoverability:arguments];
        }
        if(ckks_policy_flag) {
            return [ctl refetchCKKSPolicy:arguments];
        }
        if (ttr_flag) {
            if (radarNumber == NULL) {
                radarNumber = "1";
            }
            return [ctl tapToRadar:@"action" description:@"description" radar:[NSString stringWithUTF8String:radarNumber]];
        }
        if(resetAccountCDPContent){
            return [ctl resetAccountCDPContentsWithArguments:arguments idmsTargetContext:idmsTargetContextString idmsCuttlefishPassword:idmsCuttlefishPasswordString notifyIdMS:notifyIdMS ];
        }
        if(createCustodianRecoveryKey) {
            return [ctl createCustodianRecoveryKeyWithArguments:arguments json:json timeout:timeout];
        }
        if(joinWithCustodianRecoveryKey) {
            if (!wrappingKey || !wrappedKey || !custodianUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl joinWithCustodianRecoveryKeyWithArguments:arguments
                                                      wrappingKey:wrappingKey
                                                       wrappedKey:wrappedKey
                                                       uuidString:custodianUUIDString
                                                          timeout:timeout];
        }
        if(preflightJoinWithCustodianRecoveryKey) {
            if (!wrappingKey || !wrappedKey || !custodianUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl preflightJoinWithCustodianRecoveryKeyWithArguments:arguments
                                                               wrappingKey:wrappingKey
                                                                wrappedKey:wrappedKey
                                                                uuidString:custodianUUIDString
                                                                   timeout:timeout];
        }
        if(removeCustodianRecoveryKey) {
            if (!custodianUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl removeCustodianRecoveryKeyWithArguments:arguments
                                                     uuidString:custodianUUIDString
                                                        timeout:timeout];
        }
        
        if (removeRecoveryKey) {
            return [ctl removeRecoveryKeyWithArguments:arguments];
        }

        if (setRecoveryKey) {
            return [ctl setRecoveryKeyWithArguments:arguments];
        }
        
        if(createInheritanceKey) {
            return [ctl createInheritanceKeyWithArguments:arguments json:json timeout:timeout];
        }
        if(generateInheritanceKey) {
            return [ctl generateInheritanceKeyWithArguments:arguments json:json timeout:timeout];
        }
        if(storeInheritanceKey) {
            if (!wrappingKey || !wrappedKey || !inheritanceUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl storeInheritanceKeyWithArguments:arguments
                                             wrappingKey:wrappingKey
                                              wrappedKey:wrappedKey
                                              uuidString:inheritanceUUIDString
                                                 timeout:timeout];
        }
        if(joinWithInheritanceKey) {
            if (!wrappingKey || !wrappedKey || !inheritanceUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl joinWithInheritanceKeyWithArguments:arguments
                                                wrappingKey:wrappingKey
                                                 wrappedKey:wrappedKey
                                                 uuidString:inheritanceUUIDString
                                                    timeout:timeout];
        }
        if(preflightJoinWithInheritanceKey) {
            if (!wrappingKey || !wrappedKey || !inheritanceUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl preflightJoinWithInheritanceKeyWithArguments:arguments
                                                         wrappingKey:wrappingKey
                                                          wrappedKey:wrappedKey
                                                          uuidString:inheritanceUUIDString
                                                             timeout:timeout];
        }
        if(removeInheritanceKey) {
            if (!inheritanceUUIDString) {
                print_usage(&args);
                return 1;
            }
            return [ctl removeInheritanceKeyWithArguments:arguments
                                               uuidString:inheritanceUUIDString
                                                  timeout:timeout];
        }

        if(enableWalrus) {
            return [ctl enableWalrusWithArguments:arguments timeout:timeout];
        }
        if(disableWalrus) {
            return [ctl disableWalrusWithArguments:arguments timeout:timeout];
        }
        
        if(enableWebAccess) {
            return [ctl enableWebAccessWithArguments:arguments timeout:timeout];
        }
        if(disableWebAccess) {
            return [ctl disableWebAccessWithArguments:arguments timeout:timeout];
        }
        
        if(fetchAccountSettings) {
            return [ctl fetchAccountSettingsWithArguments:arguments json:json];
        }
        if(fetchAccountWideSettings) {
            return [ctl fetchAccountWideSettingsWithArguments:arguments forceFetch:forceFetch json:json];
        }

        if(er_trigger) {
            return (int)[escrowctl trigger];
        }
        if(er_status) {
            return (int)[escrowctl status];
        }
        if(er_reset) {
            return (int)[escrowctl reset];
        }
        if(er_store) {
            return (int)[escrowctl storePrerecordsInEscrow];
        }

#if TARGET_OS_WATCH
        if (pairme) {
            dispatch_semaphore_t sema = dispatch_semaphore_create(0);
            OTPairingInitiateWithCompletion(NULL, ^(bool success, NSError *pairingError) {
                if (success) {
                    printf("successfully paired with companion\n");
                } else {
                    printf("failed to pair with companion: %s\n", pairingError.description.UTF8String);
                }
                dispatch_semaphore_signal(sema);
            });
            dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
            return 0;
        }
#endif /* TARGET_OS_WATCH */
        if (printAccountMetadata) {
            return [ctl printAccountMetadataWithArguments:arguments json:json];
        }

        print_usage(&args);
        return 1;
    }
    return 0;
}
