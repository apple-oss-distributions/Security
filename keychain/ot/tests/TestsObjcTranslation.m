#import "TestsObjcTranslation.h"
#import <OCMock/OCMock.h>

#import <Security/SecItemPriv.h>
#import <SecurityFoundation/SecurityFoundation.h>
#import "keychain/categories/NSError+UsefulConstructors.h"
#import "keychain/securityd/SOSCloudCircleServer.h"
#import "keychain/SecureObjectSync/SOSAccountPriv.h"
#import "keychain/OctagonTrust/OctagonTrust.h"
#import "keychain/securityd/SecItemServer.h"

static const uint8_t signingKey_384[] = {
    0x04, 0xe4, 0x1b, 0x3e, 0x88, 0x81, 0x9f, 0x3b, 0x80, 0xd0, 0x28, 0x1c,
    0xd9, 0x07, 0xa0, 0x8c, 0xa1, 0x89, 0xa8, 0x3b, 0x69, 0x91, 0x17, 0xa7,
    0x1f, 0x00, 0x31, 0x91, 0x82, 0x89, 0x1f, 0x5c, 0x44, 0x2d, 0xd6, 0xa8,
    0x22, 0x1f, 0x22, 0x7d, 0x27, 0x21, 0xf2, 0xc9, 0x75, 0xf2, 0xda, 0x41,
    0x61, 0x55, 0x29, 0x11, 0xf7, 0x71, 0xcf, 0x66, 0x52, 0x2a, 0x27, 0xfe,
    0x77, 0x1e, 0xd4, 0x3d, 0xfb, 0xbc, 0x59, 0xe4, 0xed, 0xa4, 0x79, 0x2a,
    0x9b, 0x73, 0x3e, 0xf4, 0xf4, 0xe3, 0xaf, 0xf2, 0x8d, 0x34, 0x90, 0x92,
    0x47, 0x53, 0xd0, 0x34, 0x1e, 0x49, 0x87, 0xeb, 0x11, 0x89, 0x0f, 0x9c,
    0xa4, 0x99, 0xe8, 0x4f, 0x39, 0xbe, 0x21, 0x94, 0x88, 0xba, 0x4c, 0xa5,
    0x6a, 0x60, 0x1c, 0x2f, 0x77, 0x80, 0xd2, 0x73, 0x14, 0x33, 0x46, 0x5c,
    0xda, 0xee, 0x13, 0x8a, 0x3a, 0xdb, 0x4e, 0x05, 0x4d, 0x0f, 0x6d, 0x96,
    0xcd, 0x28, 0xab, 0x52, 0x4c, 0x12, 0x2b, 0x79, 0x80, 0xfe, 0x9a, 0xe4,
    0xf4
};

@implementation TestsObjectiveC : NSObject
+ (void)setNewRecoveryKeyWithData:(OTConfigurationContext *)ctx
                      recoveryKey:(NSString*)recoveryKey
                            reply:(void(^)(void* rk,
                                           NSError* _Nullable error))reply
{
    [OTClique setNewRecoveryKeyWithData:ctx recoveryKey:recoveryKey reply:^(SecRecoveryKey * _Nullable rk, NSError * _Nullable error) {
        reply((__bridge void*)rk, error);
    }];
}

+ (void)recoverOctagonUsingData:(OTConfigurationContext *)ctx
                    recoveryKey:(NSString*)recoveryKey
                          reply:(void(^)(NSError* _Nullable error))reply
{
    [OTClique recoverOctagonUsingData: ctx recoveryKey:recoveryKey reply:reply];
}

+ (BOOL)saveCoruptDataToKeychainForContainer:(NSString*)containerName
                                   contextID:(NSString*)contextID
                                       error:(NSError**)error
{
    NSData* signingFromBytes = [[NSData alloc] initWithBytes:signingKey_384 length:sizeof(signingKey_384)];

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
                                    (id)kSecValueData : signingFromBytes,
                                    (id)kSecAttrSynchronizable : @NO,
                                    (id)kSecAttrSysBound : @(kSecSecAttrSysBoundPreserveDuringRestore),
                                    } mutableCopy];

    CFTypeRef result = NULL;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)query, &result);

    NSError* localerror = nil;

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
                                  description: [NSString stringWithFormat:@"SecItemAdd: %d", (int)status]];
    }

    if(localerror) {
        if(error) {
            *error = localerror;
        }
        return false;
    } else {
        return true;
    }
}

+ (NSData* _Nullable)copyInitialSyncData:(SOSInitialSyncFlags)flags error:(NSError**)error
{
    CFErrorRef cferror = NULL;
    NSData* result = CFBridgingRelease(SOSCCCopyInitialSyncData_Server(flags, &cferror));

    if(cferror && error) {
        *error = CFBridgingRelease(cferror);
    }

    return result;
}

+ (NSDictionary* _Nullable)copyPiggybackingInitialSyncData:(NSData*)data
{
    const uint8_t* der = [data bytes];
    const uint8_t *der_end = der + [data length];

    NSDictionary* results = SOSPiggyCopyInitialSyncData(&der, der_end);
    return results;
}

+ (BOOL)testSecKey:(CKKSSelves*)octagonSelf error:(NSError**)error
{
    id<CKKSSelfPeer> currentSelfPeer = octagonSelf.currentSelf;

    NSData* signingFullKey = currentSelfPeer.signingKey.keyData;

    SecKeyRef octagonSigningPubSecKey = CFRetainSafe(currentSelfPeer.publicSigningKey.secKey);
    SecKeyRef octagonEncryptionPubSecKey = CFRetainSafe(currentSelfPeer.publicEncryptionKey.secKey);

    NSError* localerror = nil;

    bool savedSigningKey = SOSCCSaveOctagonKeysToKeychain(@"Octagon Peer Signing ID for Test-ak",
                                                          signingFullKey,
                                                          384,
                                                          octagonSigningPubSecKey,
                                                          &localerror);
    if(!savedSigningKey) {
        if(error) {
            *error = localerror;
        }
        CFReleaseNull(octagonSigningPubSecKey);
        CFReleaseNull(octagonEncryptionPubSecKey);
        return NO;
    }

    // Okay, can we load this key pair?

    // Try the SPI route first
    CFErrorRef cferror = NULL;
    SecKeyRef signingPrivateKey = SecKeyCopyMatchingPrivateKey(octagonSigningPubSecKey, &cferror);
    if(!signingPrivateKey) {
        if(error) {
            *error = CFBridgingRelease(cferror);
        } else {
            CFReleaseNull(cferror);
        }
        CFReleaseNull(octagonSigningPubSecKey);
        CFReleaseNull(octagonEncryptionPubSecKey);
        return NO;
    }

    // and can you get the persistent ref from that private key?
    CFDataRef pref = NULL;
    OSStatus status = SecKeyCopyPersistentRef(signingPrivateKey, &pref);
    if(status != errSecSuccess) {
        if(error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:status
                                  description:@"Failed to copy persistent ref"];
        }
        CFReleaseNull(pref);
        CFReleaseNull(octagonSigningPubSecKey);
        CFReleaseNull(octagonEncryptionPubSecKey);
        return NO;
    }


    SFECKeyPair *signingFullKeyPair = [[SFECKeyPair alloc] initWithData:signingFullKey
                                                              specifier:[[SFECKeySpecifier alloc] initWithCurve:SFEllipticCurveNistp384]
                                                                  error:&localerror];
    if(!signingFullKey) {
        if(error) {
            *error = localerror;
        }
        CFReleaseNull(octagonSigningPubSecKey);
        CFReleaseNull(octagonEncryptionPubSecKey);
        return NO;
    }

    CFDataRef prefFromSF = NULL;
    OSStatus statusFromSF = SecKeyCopyPersistentRef(signingFullKeyPair.secKey, &prefFromSF);
    if(statusFromSF != errSecSuccess) {
        if(error) {
            *error = [NSError errorWithDomain:NSOSStatusErrorDomain
                                         code:statusFromSF
                                  description:@"Failed to copy persistent ref"];
        }
        CFReleaseNull(pref);
        CFReleaseNull(octagonSigningPubSecKey);
        CFReleaseNull(octagonEncryptionPubSecKey);
        return NO;
    }

    CFReleaseNull(pref);
    CFReleaseNull(octagonSigningPubSecKey);
    CFReleaseNull(octagonEncryptionPubSecKey);

    return YES;
}

+ (BOOL)addNRandomKeychainItemsWithoutUpgradedPersistentRefs:(int64_t)number
{
    SecKeychainSetOverrideStaticPersistentRefsIsEnabled(false);
    
    NSDictionary* addQuery = nil;
    CFTypeRef result = NULL;
    
    for(int i = 0; i< number; i++) {
        addQuery = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                      (id)kSecValueData : [@"uuid" dataUsingEncoding:NSUTF8StringEncoding],
                      (id)kSecAttrAccount : [NSString stringWithFormat:@"testKeychainItemUpgradePhase%dAccount%d", i, i],
                      (id)kSecAttrService : @"TestUUIDPersistentRefService",
                      (id)kSecUseDataProtectionKeychain : @(YES),
                      (id)kSecAttrAccessible : (id)kSecAttrAccessibleWhenUnlocked,
                      (id)kSecReturnAttributes : @(YES),
                      (id)kSecReturnPersistentRef : @(YES)
        };
        
        result = NULL;
        SecItemAdd((__bridge CFDictionaryRef)addQuery, &result);
    }
    
    SecKeychainSetOverrideStaticPersistentRefsIsEnabled(true);
    return YES;
}

+ (BOOL)expectXNumberOfItemsUpgraded:(int64_t)expected
{
    int64_t upgraded = 0;
    
    NSDictionary *query = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                             (id)kSecUseDataProtectionKeychain : @(YES),
                             (id)kSecReturnAttributes : @(YES),
                             (id)kSecReturnPersistentRef : @(YES),
                             (id)kSecMatchLimit : (id)kSecMatchLimitAll,
    };
    
    CFTypeRef items = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &items);
    
    for (NSDictionary *item in (__bridge NSArray*)items) {
        NSData* pref = item[(id)kSecValuePersistentRef];
        if ([pref length] == 20) {
            upgraded+=1;
        }
    }
    
    return (upgraded == expected);
}

+ (BOOL)checkAllPersistentRefBeenUpgraded
{
    BOOL allUpgraded = YES;
    
    NSDictionary *query = @{ (id)kSecClass : (id)kSecClassGenericPassword,
                             (id)kSecUseDataProtectionKeychain : @(YES),
                             (id)kSecReturnAttributes : @(YES),
                             (id)kSecReturnPersistentRef : @(YES),
                             (id)kSecMatchLimit : (id)kSecMatchLimitAll,
    };
    
    CFTypeRef items = NULL;
    SecItemCopyMatching((__bridge CFDictionaryRef)query, &items);
    
    for (NSDictionary *item in (__bridge NSArray*)items) {
        NSData* pref = item[(id)kSecValuePersistentRef];
        if ([pref length] == 20) {
            allUpgraded &= YES;
        } else {
            allUpgraded &= NO;
        }
    }
    
    return allUpgraded;
}

+ (NSNumber* _Nullable)lastRowID
{
    return (__bridge NSNumber*) lastRowIDHandledForTests();
}

+ (void)setError:(int)errorCode
{
    NSString* descriptionString = [NSString stringWithFormat:@"Fake error %d for testing", errorCode];
    CFErrorRef error = (__bridge CFErrorRef)[NSError errorWithDomain:(id)kSecErrorDomain code:errorCode userInfo:@{NSLocalizedDescriptionKey : descriptionString}];
    setExpectedErrorForTests(error);
}

+ (void)clearError
{
    clearTestError();
}

+ (void)clearLastRowID
{
    clearLastRowIDHandledForTests();
}

+ (void)clearErrorInsertionDictionary
{
    clearRowIDAndErrorDictionary();
}

+ (void)setErrorAtRowID:(int)errorCode
{
    CFMutableDictionaryRef rowIDToErrorDictionary = CFDictionaryCreateMutableForCFTypes(kCFAllocatorDefault);

    NSString* descriptionString = [NSString stringWithFormat:@"Fake error %d for testing", errorCode];

    CFErrorRef error = (__bridge CFErrorRef)[NSError errorWithDomain:(id)kSecErrorDomain code:errorCode userInfo:@{NSLocalizedDescriptionKey : descriptionString}];
    CFNumberRef rowID = CFBridgingRetain([[NSNumber alloc]initWithInt:150]);
    CFDictionaryAddValue(rowIDToErrorDictionary, rowID, error);
    
    setRowIDToErrorDictionary(rowIDToErrorDictionary);

    CFReleaseNull(rowID);
}

@end

@interface OctagonTrustCliqueBridge ()
@property OTClique* clique;
@end
@implementation OctagonTrustCliqueBridge
- (instancetype)initWithClique:(OTClique*)clique
{
    if((self = [super init])) {
        _clique = clique;
    }
    return self;
}

- (BOOL)setLocalSecureElementIdentity:(OTSecureElementPeerIdentity*)secureElementIdentity
                                error:(NSError**)error
{
    return [self.clique setLocalSecureElementIdentity:secureElementIdentity
                                                error:error];
}

- (BOOL)removeLocalSecureElementIdentityPeerID:(NSData*)sePeerID
                                         error:(NSError**)error
{
    return [self.clique removeLocalSecureElementIdentityPeerID:sePeerID
                                                         error:error];
}


- (OTCurrentSecureElementIdentities* _Nullable)fetchTrustedSecureElementIdentities:(NSError**)error
{
    return [self.clique fetchTrustedSecureElementIdentities:error];
}


- (BOOL)waitForPriorityViewKeychainDataRecovery:(NSError**)error
{
    return [self.clique waitForPriorityViewKeychainDataRecovery:error];
}

@end
