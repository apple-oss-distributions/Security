
#if OCTAGON

#import <Security/Security.h>
#import <Security/SecItemPriv.h>
#import "OSX/sec/Security/SecItemShim.h"

#import "OSX/utilities/SecCFRelease.h"

#import "OTAccountMetadataClassC+KeychainSupport.h"
#import "keychain/categories/NSError+UsefulConstructors.h"
#import <OctagonTrust/OTSecureElementPeerIdentity.h>

#import "keychain/ot/OTDefines.h"
#import "keychain/ot/OTConstants.h"
#import "keychain/ckks/CKKSTLKShare.h"
#import <TrustedPeers/TPSyncingPolicy.h>
#import <TrustedPeers/TPPBSecureElementIdentity.h>

@implementation OTAccountMetadataClassC (KeychainSupport)

- (BOOL)saveToKeychainForContainer:(NSString*)containerName
                         contextID:(NSString*)contextID
                   personaAdapter:(id<OTPersonaAdapter>)personaAdapter
               personaUniqueString:(NSString* _Nullable)personaUniqueString
                             error:(NSError**)error
{
    __block NSError* localerror = nil;

    [personaAdapter performBlockWithPersonaIdentifier:personaUniqueString block:^{
        NSMutableDictionary* query = [@{
                                        (id)kSecClass : (id)kSecClassInternetPassword,
                                        (id)kSecAttrAccessible: (id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
                                        (id)kSecUseDataProtectionKeychain : @YES,
                                        (id)kSecAttrAccessGroup: @"com.apple.security.octagon",
                                        (id)kSecAttrDescription: [NSString stringWithFormat:@"Octagon Account State (%@,%@)", containerName, contextID],
                                        (id)kSecAttrServer: [NSString stringWithFormat:@"octagon-%@", containerName],
                                        (id)kSecAttrAccount: [NSString stringWithFormat:@"octagon-%@", containerName], // Really should be alt-DSID, no?
                                        (id)kSecAttrPath: [NSString stringWithFormat:@"octagon-%@", contextID],
                                        (id)kSecAttrIsInvisible: @YES,
                                        (id)kSecValueData : self.data,
                                        (id)kSecAttrSynchronizable : @NO,
                                        (id)kSecAttrSysBound : @(kSecSecAttrSysBoundPreserveDuringRestore),
                                        } mutableCopy];

        CFTypeRef result = NULL;
        OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, &result);

        // Did SecItemAdd fall over due to an existing item?
        if(status == errSecDuplicateItem) {
            // Add every primary key attribute to this find dictionary
            NSMutableDictionary* findQuery = [[NSMutableDictionary alloc] init];
            findQuery[(id)kSecClass]              = query[(id)kSecClass];
            findQuery[(id)kSecAttrSynchronizable] = query[(id)kSecAttrSynchronizable];
            findQuery[(id)kSecAttrSyncViewHint]   = query[(id)kSecAttrSyncViewHint];
            findQuery[(id)kSecAttrAccessGroup]    = query[(id)kSecAttrAccessGroup];
            findQuery[(id)kSecAttrAccount]        = query[(id)kSecAttrAccount];
            findQuery[(id)kSecAttrServer]         = query[(id)kSecAttrServer];
            findQuery[(id)kSecAttrPath]           = query[(id)kSecAttrPath];
            findQuery[(id)kSecUseDataProtectionKeychain] = query[(id)kSecUseDataProtectionKeychain];

            NSMutableDictionary* updateQuery = [query mutableCopy];
            updateQuery[(id)kSecClass] = nil;

            status = SecItemUpdate((__bridge CFDictionaryRef)findQuery, (__bridge CFDictionaryRef)updateQuery);

            if(status) {
                localerror = [NSError errorWithDomain:NSOSStatusErrorDomain
                                                 code:status
                                          description:[NSString stringWithFormat:@"SecItemUpdate: %d", (int)status]];
            }
        } else if(status != 0) {
            localerror = [NSError errorWithDomain:NSOSStatusErrorDomain
                                             code:status
                                      description: [NSString stringWithFormat:@"SecItemUpdate: %d", (int)status]];
        }
    }];

    if(localerror) {
        if(error) {
            *error = localerror;
        }
        return NO;
    } else {
        return YES;
    }
}

+ (BOOL)deleteFromKeychainForContainer:(NSString*)containerName
                             contextID:(NSString*)contextID
                       personaAdapter:(id<OTPersonaAdapter>)personaAdapter
                   personaUniqueString:(NSString* _Nullable)personaUniqueString
                                 error:(NSError**)error  __attribute__((swift_error(nonnull_error)))
{
    __block OSStatus status = -1;

    [personaAdapter performBlockWithPersonaIdentifier: personaUniqueString block:^{
        NSMutableDictionary* query = [@{
                                    (id)kSecClass : (id)kSecClassInternetPassword,
                                    (id)kSecUseDataProtectionKeychain : @YES,
                                    (id)kSecAttrAccessGroup: @"com.apple.security.octagon",
                                    (id)kSecAttrServer: [NSString stringWithFormat:@"octagon-%@", containerName],
                                    (id)kSecAttrAccount: [NSString stringWithFormat:@"octagon-%@", containerName],
                                    (id)kSecAttrPath: [NSString stringWithFormat:@"octagon-%@", contextID],
                                    (id)kSecAttrSynchronizable : @NO,
                                    } mutableCopy];

        status = SecItemDelete((__bridge CFDictionaryRef)query);
    }];
    
    if(status) {
        if(error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:status
                                     userInfo:@{NSLocalizedDescriptionKey:
                                                    [NSString stringWithFormat:@"SecItemDelete: %d", (int)status]}];
        }
        return NO;
    }
    return YES;
}

+ (OTAccountMetadataClassC* _Nullable)loadFromKeychainForContainer:(NSString*)containerName
                                                         contextID:(NSString*)contextID
                                                   personaAdapter:(id<OTPersonaAdapter>)personaAdapter
                                               personaUniqueString:(NSString* _Nullable)personaUniqueString
                                                             error:(NSError**)error
{
    __block OTAccountMetadataClassC* state = nil;
    __block NSError* localError = nil;
    
    [personaAdapter performBlockWithPersonaIdentifier:personaUniqueString block:^{

        NSMutableDictionary* query = [@{
                                        (id)kSecClass : (id)kSecClassInternetPassword,
                                        (id)kSecUseDataProtectionKeychain : @YES,
                                        (id)kSecAttrAccessGroup: @"com.apple.security.octagon",
                                        (id)kSecAttrServer: [NSString stringWithFormat:@"octagon-%@", containerName],
                                        (id)kSecAttrAccount: [NSString stringWithFormat:@"octagon-%@", containerName],
                                        (id)kSecAttrPath: [NSString stringWithFormat:@"octagon-%@", contextID],
                                        (id)kSecAttrSynchronizable : @NO,
                                        (id)kSecReturnAttributes: @YES,
                                        (id)kSecReturnData: @YES,
                                        } mutableCopy];

        CFTypeRef result = NULL;
        OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);

        if(status) {
            CFReleaseNull(result);

            localError = [NSError errorWithDomain:NSOSStatusErrorDomain
                                             code:status
                                         userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"SecItemCopyMatching: %d", (int)status]}];
            return;
        }

        NSDictionary* resultDict = CFBridgingRelease(result);

        state = [[OTAccountMetadataClassC alloc] initWithData:resultDict[(id)kSecValueData]];
        if(!state) {
            localError = [NSError errorWithDomain:OctagonErrorDomain code:OctagonErrorDeserializationFailure description:@"couldn't deserialize account state"];
            NSError* deleteError = nil;
            BOOL deleted = [OTAccountMetadataClassC deleteFromKeychainForContainer:containerName
                                                                         contextID:contextID
                                                                    personaAdapter:personaAdapter
                                                               personaUniqueString:personaUniqueString
                                                                             error:&deleteError];
            if(deleted == NO || deleteError) {
                secnotice("octagon", "failed to reset account metadata in keychain, %@", deleteError);
            }
            return;
        }

        //check if an account state has the appropriate attributes
        if(resultDict[(id)kSecAttrSysBound] == nil || ![resultDict[(id)kSecAttrAccessible] isEqualToString:(id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]){
            [state saveToKeychainForContainer:containerName
                                    contextID:contextID
                               personaAdapter:personaAdapter
                          personaUniqueString:personaUniqueString
                                        error:&localError];
        }
    }];
    
    if(localError && error) {
        *error = localError;
    }

    return state;
}

@end

#pragma mark - Field Coding support

@implementation OTAccountMetadataClassC (NSSecureCodingSupport)

- (void)setTPSyncingPolicy:(TPSyncingPolicy*)policy
{
    if(policy) {
        NSKeyedArchiver *archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
        [policy encodeWithCoder:archiver];
        self.syncingPolicy = archiver.encodedData;
    } else {
        self.syncingPolicy = nil;
    }
}

- (TPSyncingPolicy* _Nullable)getTPSyncingPolicy
{
    NSKeyedUnarchiver *coder = [[NSKeyedUnarchiver alloc] initForReadingFromData:self.syncingPolicy error:nil];
    TPSyncingPolicy* policy = [[TPSyncingPolicy alloc] initWithCoder:coder];
    [coder finishDecoding];

    return policy;
}

- (void)setTLKSharesPairedWithVoucher:(NSArray<CKKSTLKShare*>*)newTLKShares
{
    NSMutableArray<NSData*>* tlkSharesForStorage = [NSMutableArray array];

    for(CKKSTLKShare* share in newTLKShares) {
        NSKeyedArchiver *archiver = [[NSKeyedArchiver alloc] initRequiringSecureCoding:YES];
        [share encodeWithCoder:archiver];
        [tlkSharesForStorage addObject:archiver.encodedData];
    }

    self.tlkSharesForVouchedIdentitys = tlkSharesForStorage;
}

- (NSArray<CKKSTLKShare*>*)getTLKSharesPairedWithVoucher
{
    NSMutableArray<CKKSTLKShare*>* tlkShares = [NSMutableArray array];

    for(NSData* shareData in self.tlkSharesForVouchedIdentitys) {
        NSKeyedUnarchiver *coder = [[NSKeyedUnarchiver alloc] initForReadingFromData:shareData error:nil];
        CKKSTLKShare* tlkShare = [[CKKSTLKShare alloc] initWithCoder:coder];
        [coder finishDecoding];

        [tlkShares addObject:tlkShare];
    }

    return tlkShares;
}

- (void)setOctagonSecureElementIdentity:(OTSecureElementPeerIdentity *)secureElementIdentity
{
    TPPBSecureElementIdentity* tppbSEI = [[TPPBSecureElementIdentity alloc] init];
    tppbSEI.peerIdentifier = secureElementIdentity.peerIdentifier;
    tppbSEI.peerData = secureElementIdentity.peerData;

    self.secureElementIdentity = tppbSEI.data;
}

- (TPPBSecureElementIdentity* _Nullable)parsedSecureElementIdentity
{
    NSData* d = self.secureElementIdentity;
    if(!d || [d length] == 0) {
        return nil;
    }

    return [[TPPBSecureElementIdentity alloc] initWithData:d];
}

- (NSDate* _Nullable)memoizedLastHealthCheck
{
    return [self _dateForMillisecondsSinceEpoch:self.lastHealthCheckup];
}

- (NSDate* _Nullable)memoizedLastEscrowRepairTriggered
{
    return [self _dateForMillisecondsSinceEpoch:self.lastEscrowRepairTriggered];
}

- (NSDate* _Nullable)memoizedLastEscrowRepairAttempted
{
    return [self _dateForMillisecondsSinceEpoch:self.lastEscrowRepairAttempted];
}

- (NSDate* _Nullable)_dateForMillisecondsSinceEpoch:(uint64_t)timestamp
{
    NSDate* result = nil;
    if (timestamp != 0) {
        result = [[NSDate alloc] initWithTimeIntervalSince1970:(NSTimeInterval)timestamp / 1000.0];
    }
    return result;
}

@end

#endif // OCTAGON
