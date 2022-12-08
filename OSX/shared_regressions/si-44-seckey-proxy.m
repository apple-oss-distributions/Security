/*
 * Copyright (c) 2016 Apple Inc. All Rights Reserved.
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
#import <Security/SecKeyPriv.h>
#import <Security/SecIdentityPriv.h>
#import <Security/SecKeyProxy.h>

#import "shared_regressions.h"

static void test_key_proxy_connect(void) {
    NSError *error;
    id serverKey = CFBridgingRelease(SecKeyCreateRandomKey((CFDictionaryRef)@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, (id)kSecAttrKeySizeInBits: @(256)}, (void *)&error));
    ok(serverKey != NULL, "generated local ec256 keypair");
    SecKeyProxy *keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    SecKeyRef localKey = [SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error];
    isnt(localKey, NULL,  "connected to remote key, error %@", error);
    ok(CFGetTypeID(localKey) == SecKeyGetTypeID(), "Connected key is really SecKey");
    
    // Try another connection to the proxy.
    SecKeyRef secondKey = [SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error];
    isnt(secondKey, NULL, "2nd connection should not be refused");
    isnt(SecKeyGetBlockSize(secondKey), (size_t)0, "2nd connections working normally");

    // Even after deleting (not invalidating!) proxy, existing connections should work right.
    NSXPCListenerEndpoint *endpoint = keyProxy.endpoint;
    keyProxy = nil;

    // However, connection to it should not be possible any more.
    CFRelease(secondKey);
    secondKey = [SecKeyProxy createKeyFromEndpoint:endpoint error:&error];
    is(secondKey, NULL, "connecting to deleted proxy should not be possible");

    // Create new proxy and invalidate it (idempotent, so we try invalidate multiple times).
    keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    endpoint = keyProxy.endpoint;
    [keyProxy invalidate];
    [keyProxy invalidate];
    secondKey = [SecKeyProxy createKeyFromEndpoint:endpoint error:&error];
    is(secondKey, NULL, "connection to invalidated proxy should be refused.");

    // Invalidate connected proxy, make sure that remote key does not work as expected.
    keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    secondKey = [SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error];
    isnt(secondKey, NULL, "connecting to proxy failed.");
    
    is(SecKeyGetBlockSize((__bridge SecKeyRef)serverKey), SecKeyGetBlockSize(secondKey), "connected key should work fine");
    [keyProxy invalidate];
    is(SecKeyGetBlockSize(secondKey), (size_t)0, "disconnected key should fail");
    CFRelease(secondKey);
}
static const int TestKeyProxyConnectCount = 10;

static void test_key_proxy_simple_ops(void) {
    NSError *error;
    id serverKey = CFBridgingRelease(SecKeyCreateRandomKey((CFDictionaryRef)@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, (id)kSecAttrKeySizeInBits: @(256)}, (void *)&error));
    SecKeyProxy *keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    id localKey = CFBridgingRelease([SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error]);
    NSDictionary *serverAttributes = CFBridgingRelease(SecKeyCopyAttributes((SecKeyRef)serverKey));
    NSDictionary *localAttributes = CFBridgingRelease(SecKeyCopyAttributes((SecKeyRef)localKey));
    isnt(localAttributes, nil, "attributes for local remote key failed");
    ok([serverAttributes isEqual:localAttributes], "local and remote attributes should be identical");
    
    // Just call description, there is no reasonable way to test the contents, not crashing is enough.
    CFBridgingRelease(CFCopyDescription((SecKeyRef)localKey));
    
    is(SecKeyGetAlgorithmId((__bridge SecKeyRef)serverKey), SecKeyGetAlgorithmId((__bridge SecKeyRef)localKey), "GetAlgorithmId failed for remote");
}
static const int TestKeyProxySimpleOpsCount = 3;

static void test_crypto_sign(id key1, id key2, SecKeyAlgorithm algorithm) {
    id pk1 = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)key1));
    isnt(pk1, nil, "failed to get pubkey from key %@", key1);
    id pk2 = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)key2));
    isnt(pk2, nil, "failed to get pubkey from key %@", key2);
    ok(SecKeyIsAlgorithmSupported((SecKeyRef)key1, kSecKeyOperationTypeSign, algorithm));
    ok(SecKeyIsAlgorithmSupported((SecKeyRef)key2, kSecKeyOperationTypeSign, algorithm));

    NSData *message = [@"Hello" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *signature1 = CFBridgingRelease(SecKeyCreateSignature((SecKeyRef)key1, algorithm, (CFDataRef)message, (void *)&error));
    isnt(signature1, nil, "failed to sign data with algorithm %@: %@", algorithm, error);
    ok(SecKeyVerifySignature((SecKeyRef)pk2, algorithm, (CFDataRef)message, (CFDataRef)signature1, (void *)&error), "failed to verify data with algorithm %@: %@", algorithm, error);

    message = [@"Hello" dataUsingEncoding:NSUTF8StringEncoding];
    error = nil;
    NSData *signature2 = CFBridgingRelease(SecKeyCreateSignature((SecKeyRef)key2, algorithm, (CFDataRef)message, (void *)&error));
    isnt(signature2, nil, "failed to sign data with algorithm %@: %@", algorithm, error);
    ok(SecKeyVerifySignature((SecKeyRef)pk1, algorithm, (CFDataRef)message, (CFDataRef)signature1, (void *)&error), "failed to verify data with algorithm %@: %@", algorithm, error);
}
static const int TestKeyCryptoSignCount = 8;

static void test_crypto_encrypt(id key1, id key2, SecKeyAlgorithm algorithm) {
    id pk1 = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)key1));
    isnt(pk1, nil, "failed to get pubkey from key %@", key1);
    id pk2 = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)key2));
    isnt(pk2, nil, "failed to get pubkey from key %@", key2);
    ok(SecKeyIsAlgorithmSupported((SecKeyRef)key1, kSecKeyOperationTypeDecrypt, algorithm));
    ok(SecKeyIsAlgorithmSupported((SecKeyRef)key2, kSecKeyOperationTypeDecrypt, algorithm));

    NSData *message = [@"Hello" dataUsingEncoding:NSUTF8StringEncoding];
    NSError *error;
    NSData *ciphertext1 = CFBridgingRelease(SecKeyCreateEncryptedData((SecKeyRef)pk1, algorithm, (CFDataRef)message, (void *)&error));
    isnt(ciphertext1, nil, "failed to encrypt data with algorithm %@: %@", algorithm, error);
    NSData *plaintext1 = CFBridgingRelease(SecKeyCreateDecryptedData((SecKeyRef)key2, algorithm, (CFDataRef)ciphertext1, (void *)&error));
    ok([plaintext1 isEqualToData:message], "encrypt/decrypt differs from message: %@ vs %@", message, plaintext1);
    
    message = [@"Hello" dataUsingEncoding:NSUTF8StringEncoding];
    error = nil;
    NSData *ciphertext2 = CFBridgingRelease(SecKeyCreateEncryptedData((SecKeyRef)pk2, algorithm, (CFDataRef)message, (void *)&error));
    isnt(ciphertext2, nil, "failed to encrypt data with algorithm %@: %@", algorithm, error);
    NSData *plaintext2 = CFBridgingRelease(SecKeyCreateDecryptedData((SecKeyRef)key1, algorithm, (CFDataRef)ciphertext2, (void *)&error));
    ok([plaintext2 isEqualToData:message], "encrypt/decrypt differs from message: %@ vs %@", message, plaintext2);
}
static const int TestKeyCryptoEncryptCount = 8;

static void test_crypto_kxchg(id key1, id key2, SecKeyAlgorithm algorithm) {
    id pk1 = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)key1));
    isnt(pk1, nil, "failed to get pubkey from key %@", key1);
    id pk2 = CFBridgingRelease(SecKeyCopyPublicKey((SecKeyRef)key2));
    isnt(pk2, nil, "failed to get pubkey from key %@", key2);
    ok(SecKeyIsAlgorithmSupported((SecKeyRef)key1, kSecKeyOperationTypeKeyExchange, algorithm));
    ok(SecKeyIsAlgorithmSupported((SecKeyRef)key2, kSecKeyOperationTypeKeyExchange, algorithm));

    NSError *error;
    NSData *result1 = CFBridgingRelease(SecKeyCopyKeyExchangeResult((SecKeyRef)key1, algorithm, (SecKeyRef)pk2, (CFDictionaryRef)@{}, (void *)&error));
    isnt(result1, nil, "failed to keyexchange data with algorithm %@: %@", algorithm, error);
    NSData *result2 = CFBridgingRelease(SecKeyCopyKeyExchangeResult((SecKeyRef)key2, algorithm, (SecKeyRef)pk1, (CFDictionaryRef)@{}, (void *)&error));
    isnt(result1, nil, "failed to keyexchange data with algorithm %@: %@", algorithm, error);
    ok([result1 isEqualToData:result2], "keyexchange results differ!");
}
static const int TestKeyCryptoKeyExchange = 7;

static void test_key_proxy_crypto_ops_RSA(void) {
    NSError *error;
    id serverKey = CFBridgingRelease(SecKeyCreateRandomKey((CFDictionaryRef)@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeySizeInBits: @(2048)}, (void *)&error));
    ok(serverKey != NULL, "generated local rsa2048 keypair: %@", error);
    SecKeyProxy *keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    id localKey = CFBridgingRelease([SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error]);
    isnt(localKey, NULL,  "connected to remote key, error %@", error);
    
    test_crypto_sign(localKey, serverKey, kSecKeyAlgorithmRSASignatureMessagePSSSHA1);
    test_crypto_sign(serverKey, localKey, kSecKeyAlgorithmRSASignatureMessagePSSSHA256);
    
    test_crypto_encrypt(localKey, serverKey, kSecKeyAlgorithmRSAEncryptionOAEPSHA1);
    test_crypto_encrypt(serverKey, localKey, kSecKeyAlgorithmRSAEncryptionOAEPSHA256);
}
static const int TestKeyCryptoOpsRSACount = 2 + TestKeyCryptoSignCount * 2 + TestKeyCryptoEncryptCount * 2;

static void test_key_proxy_crypto_ops_EC(void) {
    NSError *error;
    id serverKey = CFBridgingRelease(SecKeyCreateRandomKey((CFDictionaryRef)@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, (id)kSecAttrKeySizeInBits: @(256)}, (void *)&error));
    ok(serverKey != NULL, "generated local ec256 keypair: %@", error);
    SecKeyProxy *keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    id localKey = CFBridgingRelease([SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error]);
    isnt(localKey, NULL,  "connected to remote key, error %@", error);
    
    test_crypto_sign(localKey, serverKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA1);
    test_crypto_sign(serverKey, localKey, kSecKeyAlgorithmECDSASignatureMessageX962SHA256);
    
    test_crypto_encrypt(localKey, serverKey, kSecKeyAlgorithmECIESEncryptionCofactorX963SHA1AESGCM);
    test_crypto_encrypt(serverKey, localKey, kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM);
    
    test_crypto_kxchg(localKey, serverKey, kSecKeyAlgorithmECDHKeyExchangeStandard);
}
static const int TestKeyCryptoOpsECCount = 2 + TestKeyCryptoSignCount * 2 + TestKeyCryptoEncryptCount * 2 + TestKeyCryptoKeyExchange * 1;

static void test_key_proxy_connection_handlers(void) {
    NSError *error;
    id serverKey = CFBridgingRelease(SecKeyCreateRandomKey((CFDictionaryRef)@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, (id)kSecAttrKeySizeInBits: @(256)}, (void *)&error));
    ok(serverKey != NULL, "generated local ec256 keypair: %@", error);
    SecKeyProxy *keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)serverKey];
    __block int connectCalled = 0;
    __block int disconnectCalled = 0;
    keyProxy.clientConnectionHandler = ^(BOOL firstClientConnected) {
        connectCalled = firstClientConnected ? 2 : 1;
    };
    keyProxy.clientDisconnectionHandler = ^(BOOL lastClientDisconnected) {
        disconnectCalled = lastClientDisconnected ? 2 : 1;
    };
    
    @autoreleasepool {
        id localKey1 = CFBridgingRelease([SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error]);
        isnt(localKey1, NULL,  "connected to remote key, error %@", error);
        is(connectCalled, 2, "connection handler was not invoked as expected");
        is(disconnectCalled, 0, "disconnection handler was unexpectedly invoked");
        connectCalled = disconnectCalled = 0;
    
        @autoreleasepool {
            id localKey2 = CFBridgingRelease([SecKeyProxy createKeyFromEndpoint:keyProxy.endpoint error:&error]);
            isnt(localKey2, NULL,  "connected to remote key, error %@", error);
            is(connectCalled, 1, "connection handler was not invoked as expected");
            is(disconnectCalled, 0, "disconnection handler was unexpectedly invoked");
            connectCalled = disconnectCalled = 0;
        }

        // Notifications are asynchronous, so give them a bit of time to deliver.
        [NSThread sleepForTimeInterval:0.5];
        is(connectCalled, 0, "connection handler was unexpectedly invoked");
        is(disconnectCalled, 1, "disconnection handler was not invoked as expected");
    }

    [NSThread sleepForTimeInterval:0.5];
    is(connectCalled, 0, "connection handler was unexpectedly invoked");
    is(disconnectCalled, 2, "disconnection handler was not invoked as expected");

    keyProxy = nil;
}
static const int TestKeyProxyConnectionHandlersCount = 11;

/*
 Bag Attributes
 friendlyName: uranusLeaf
 localKeyID: 46 E0 8A 05 63 4D 17 3F CA A4 AA B6 5A DA CF BA 84 22 7C 23
 subject=/CN=uranusLeaf/emailAddress=uranus@uranus.com
 issuer=/CN=plutoCA/emailAddress=pluto@pluto.com
 */
static const uint8_t _c1[] = {
    0x30, 0x82, 0x02, 0xe0, 0x30, 0x82, 0x01, 0xc8,
    0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
    0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x05, 0x30, 0x32, 0x31,
    0x10, 0x30, 0x0e, 0x06, 0x03, 0x55, 0x04, 0x03,
    0x0c, 0x07, 0x70, 0x6c, 0x75, 0x74, 0x6f, 0x43,
    0x41, 0x31, 0x1e, 0x30, 0x1c, 0x06, 0x09, 0x2a,
    0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
    0x0c, 0x0f, 0x70, 0x6c, 0x75, 0x74, 0x6f, 0x40,
    0x70, 0x6c, 0x75, 0x74, 0x6f, 0x2e, 0x63, 0x6f,
    0x6d, 0x30, 0x1e, 0x17, 0x0d, 0x30, 0x35, 0x31,
    0x32, 0x31, 0x37, 0x30, 0x30, 0x30, 0x34, 0x32,
    0x35, 0x5a, 0x17, 0x0d, 0x30, 0x36, 0x31, 0x32,
    0x31, 0x37, 0x30, 0x30, 0x30, 0x34, 0x32, 0x35,
    0x5a, 0x30, 0x37, 0x31, 0x13, 0x30, 0x11, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a, 0x75, 0x72,
    0x61, 0x6e, 0x75, 0x73, 0x4c, 0x65, 0x61, 0x66,
    0x31, 0x20, 0x30, 0x1e, 0x06, 0x09, 0x2a, 0x86,
    0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01, 0x0c,
    0x11, 0x75, 0x72, 0x61, 0x6e, 0x75, 0x73, 0x40,
    0x75, 0x72, 0x61, 0x6e, 0x75, 0x73, 0x2e, 0x63,
    0x6f, 0x6d, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0d,
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01,
    0x0f, 0x00, 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82,
    0x01, 0x01, 0x00, 0xa6, 0x82, 0x8e, 0xc6, 0x7e,
    0xc9, 0x8c, 0x99, 0x6f, 0xb0, 0x62, 0x32, 0x35,
    0xe7, 0xdb, 0xff, 0x34, 0x84, 0xdc, 0x72, 0xa8,
    0xef, 0x22, 0x6f, 0x93, 0x63, 0x64, 0x80, 0x80,
    0x5d, 0x50, 0x7e, 0xb4, 0x2e, 0x1b, 0x93, 0x93,
    0x49, 0xca, 0xae, 0xcd, 0x34, 0x44, 0x4b, 0xd7,
    0xfa, 0x9f, 0x3c, 0xfc, 0x9e, 0x65, 0xa9, 0xfb,
    0x5e, 0x5d, 0x18, 0xa3, 0xf8, 0xb0, 0x08, 0xac,
    0x8f, 0xfd, 0x03, 0xcb, 0xbd, 0x7f, 0xa0, 0x2a,
    0xa6, 0xea, 0xca, 0xa3, 0x24, 0xef, 0x7c, 0xc3,
    0xeb, 0x95, 0xcb, 0x90, 0x3f, 0x5e, 0xde, 0x78,
    0xf2, 0x3d, 0x32, 0x72, 0xdb, 0x33, 0x6e, 0x9b,
    0x52, 0x9f, 0x0c, 0x60, 0x4a, 0x24, 0xa1, 0xf6,
    0x3b, 0x80, 0xbd, 0xa1, 0xdc, 0x40, 0x03, 0xe7,
    0xa0, 0x59, 0x1f, 0xdb, 0xb4, 0xed, 0x57, 0xdc,
    0x74, 0x0d, 0x99, 0x5a, 0x12, 0x74, 0x64, 0xaa,
    0xb6, 0xa5, 0x96, 0x75, 0xf9, 0x42, 0x43, 0xe2,
    0x52, 0xc2, 0x57, 0x23, 0x75, 0xd7, 0xa9, 0x4f,
    0x07, 0x32, 0x99, 0xbd, 0x3d, 0x44, 0xbd, 0x04,
    0x62, 0xe5, 0xb7, 0x2c, 0x0c, 0x11, 0xc5, 0xb2,
    0x2e, 0xc4, 0x12, 0x1d, 0x7f, 0x42, 0x1e, 0x71,
    0xaf, 0x39, 0x2b, 0x78, 0x47, 0x92, 0x23, 0x44,
    0xef, 0xe3, 0xc1, 0x47, 0x69, 0x5a, 0xf1, 0x48,
    0xaa, 0x37, 0xa4, 0x94, 0x6b, 0x96, 0xe5, 0x4b,
    0xfd, 0x05, 0xc7, 0x9c, 0xcc, 0x38, 0xd1, 0x47,
    0x85, 0x60, 0x7f, 0xef, 0xe9, 0x2e, 0x25, 0x08,
    0xf8, 0x7d, 0x98, 0xdd, 0x6c, 0xeb, 0x4a, 0x32,
    0x33, 0x44, 0x0b, 0x61, 0xb3, 0xf9, 0xae, 0x26,
    0x41, 0xb5, 0x38, 0xdb, 0xcf, 0x13, 0x72, 0x23,
    0x5b, 0x66, 0x20, 0x86, 0x4d, 0x24, 0xc2, 0xd4,
    0x94, 0xde, 0xe3, 0x24, 0xb7, 0xcd, 0x75, 0x9e,
    0x1d, 0x9f, 0xbc, 0xd0, 0x60, 0x34, 0x7d, 0xf8,
    0xcb, 0x41, 0x39, 0x02, 0x03, 0x01, 0x00, 0x01,
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
    0xf7, 0x0d, 0x01, 0x01, 0x05, 0x05, 0x00, 0x03,
    0x82, 0x01, 0x01, 0x00, 0x17, 0xa5, 0x22, 0xed,
    0xb8, 0x3e, 0x1f, 0x11, 0x99, 0xc5, 0xba, 0x28,
    0x3e, 0x7e, 0xa6, 0xeb, 0x02, 0x81, 0x06, 0xa1,
    0xc6, 0x80, 0xb9, 0x7e, 0x5c, 0x5a, 0x63, 0xe0,
    0x8d, 0xeb, 0xd0, 0xec, 0x9c, 0x3a, 0x94, 0x64,
    0x7c, 0x13, 0x54, 0x0d, 0xd6, 0xe3, 0x27, 0x88,
    0xa6, 0xd2, 0x4b, 0x36, 0xdd, 0x2e, 0xfa, 0x94,
    0xe5, 0x03, 0x27, 0xc9, 0xa6, 0x31, 0x02, 0xea,
    0x40, 0x77, 0x2e, 0x93, 0xc4, 0x4d, 0xe2, 0x70,
    0xe2, 0x67, 0x1c, 0xa8, 0x0d, 0xcd, 0x1a, 0x72,
    0x86, 0x2c, 0xea, 0xdc, 0x7f, 0x8c, 0x49, 0x2c,
    0xe7, 0x99, 0x13, 0xda, 0x3f, 0x58, 0x9e, 0xf5,
    0x4d, 0x3c, 0x8c, 0x1c, 0xed, 0x85, 0xa7, 0xe2,
    0xae, 0xda, 0x5f, 0xbe, 0x36, 0x1c, 0x9f, 0x5a,
    0xa0, 0xdc, 0x2a, 0xc0, 0xee, 0x71, 0x07, 0x26,
    0x8b, 0xe8, 0x8a, 0xf8, 0x2d, 0x36, 0x78, 0xc9,
    0x79, 0xfa, 0xbe, 0x98, 0x59, 0x95, 0x12, 0x24,
    0xf1, 0xda, 0x20, 0xc7, 0x78, 0xf9, 0x7c, 0x6a,
    0x24, 0x43, 0x82, 0xa8, 0x0f, 0xb1, 0x7d, 0x94,
    0xaa, 0x30, 0x35, 0xe5, 0x69, 0xdc, 0x0a, 0x0e,
    0xaf, 0x10, 0x5e, 0x1a, 0x81, 0x50, 0x5c, 0x7e,
    0x24, 0xb3, 0x07, 0x65, 0x4b, 0xc1, 0x7e, 0xc6,
    0x38, 0xdb, 0xd3, 0x6a, 0xf0, 0xd8, 0x85, 0x61,
    0x9a, 0x9f, 0xfe, 0x02, 0x46, 0x29, 0xb2, 0x9a,
    0xe2, 0x04, 0xe7, 0x72, 0xcc, 0x87, 0x46, 0xba,
    0x7d, 0xa8, 0xf9, 0xd0, 0x0f, 0x29, 0xfc, 0xfd,
    0xd1, 0xd0, 0x7f, 0x36, 0xc1, 0xd8, 0x7d, 0x88,
    0x03, 0x62, 0xf5, 0x8c, 0x00, 0xb5, 0xc2, 0x81,
    0x44, 0x67, 0x58, 0x11, 0xb4, 0x3a, 0xbb, 0xd1,
    0x8c, 0x94, 0x20, 0x60, 0xea, 0xa0, 0xac, 0xc1,
    0xf1, 0x08, 0x54, 0xb8, 0xf6, 0x5e, 0xac, 0xf1,
    0xec, 0x78, 0x69, 0x9d, 0x7e, 0x4d, 0x06, 0x3b,
    0x9b, 0x78, 0x78, 0x10
};

/*
 Bag Attributes
 friendlyName: uranusLeaf
 localKeyID: 46 E0 8A 05 63 4D 17 3F CA A4 AA B6 5A DA CF BA 84 22 7C 23
 Key Attributes: <No Attributes>
 */
static const uint8_t _k1[] = {
    0x30, 0x82, 0x04, 0xa4, 0x02, 0x01, 0x00, 0x02,
    0x82, 0x01, 0x01, 0x00, 0xa6, 0x82, 0x8e, 0xc6,
    0x7e, 0xc9, 0x8c, 0x99, 0x6f, 0xb0, 0x62, 0x32,
    0x35, 0xe7, 0xdb, 0xff, 0x34, 0x84, 0xdc, 0x72,
    0xa8, 0xef, 0x22, 0x6f, 0x93, 0x63, 0x64, 0x80,
    0x80, 0x5d, 0x50, 0x7e, 0xb4, 0x2e, 0x1b, 0x93,
    0x93, 0x49, 0xca, 0xae, 0xcd, 0x34, 0x44, 0x4b,
    0xd7, 0xfa, 0x9f, 0x3c, 0xfc, 0x9e, 0x65, 0xa9,
    0xfb, 0x5e, 0x5d, 0x18, 0xa3, 0xf8, 0xb0, 0x08,
    0xac, 0x8f, 0xfd, 0x03, 0xcb, 0xbd, 0x7f, 0xa0,
    0x2a, 0xa6, 0xea, 0xca, 0xa3, 0x24, 0xef, 0x7c,
    0xc3, 0xeb, 0x95, 0xcb, 0x90, 0x3f, 0x5e, 0xde,
    0x78, 0xf2, 0x3d, 0x32, 0x72, 0xdb, 0x33, 0x6e,
    0x9b, 0x52, 0x9f, 0x0c, 0x60, 0x4a, 0x24, 0xa1,
    0xf6, 0x3b, 0x80, 0xbd, 0xa1, 0xdc, 0x40, 0x03,
    0xe7, 0xa0, 0x59, 0x1f, 0xdb, 0xb4, 0xed, 0x57,
    0xdc, 0x74, 0x0d, 0x99, 0x5a, 0x12, 0x74, 0x64,
    0xaa, 0xb6, 0xa5, 0x96, 0x75, 0xf9, 0x42, 0x43,
    0xe2, 0x52, 0xc2, 0x57, 0x23, 0x75, 0xd7, 0xa9,
    0x4f, 0x07, 0x32, 0x99, 0xbd, 0x3d, 0x44, 0xbd,
    0x04, 0x62, 0xe5, 0xb7, 0x2c, 0x0c, 0x11, 0xc5,
    0xb2, 0x2e, 0xc4, 0x12, 0x1d, 0x7f, 0x42, 0x1e,
    0x71, 0xaf, 0x39, 0x2b, 0x78, 0x47, 0x92, 0x23,
    0x44, 0xef, 0xe3, 0xc1, 0x47, 0x69, 0x5a, 0xf1,
    0x48, 0xaa, 0x37, 0xa4, 0x94, 0x6b, 0x96, 0xe5,
    0x4b, 0xfd, 0x05, 0xc7, 0x9c, 0xcc, 0x38, 0xd1,
    0x47, 0x85, 0x60, 0x7f, 0xef, 0xe9, 0x2e, 0x25,
    0x08, 0xf8, 0x7d, 0x98, 0xdd, 0x6c, 0xeb, 0x4a,
    0x32, 0x33, 0x44, 0x0b, 0x61, 0xb3, 0xf9, 0xae,
    0x26, 0x41, 0xb5, 0x38, 0xdb, 0xcf, 0x13, 0x72,
    0x23, 0x5b, 0x66, 0x20, 0x86, 0x4d, 0x24, 0xc2,
    0xd4, 0x94, 0xde, 0xe3, 0x24, 0xb7, 0xcd, 0x75,
    0x9e, 0x1d, 0x9f, 0xbc, 0xd0, 0x60, 0x34, 0x7d,
    0xf8, 0xcb, 0x41, 0x39, 0x02, 0x03, 0x01, 0x00,
    0x01, 0x02, 0x82, 0x01, 0x00, 0x4d, 0x27, 0xf2,
    0x40, 0xc8, 0x3f, 0x5c, 0x87, 0x3c, 0xd9, 0xde,
    0xa6, 0xa5, 0x93, 0xea, 0xbd, 0x36, 0xf8, 0xd9,
    0xad, 0xc7, 0xda, 0x07, 0x7a, 0xec, 0x31, 0x02,
    0x41, 0x09, 0x3a, 0x34, 0x32, 0x82, 0x0b, 0x5b,
    0x7b, 0xe6, 0xa4, 0x2a, 0xe7, 0x14, 0xef, 0x43,
    0x36, 0x61, 0xbe, 0x20, 0x4b, 0x82, 0x43, 0x63,
    0x98, 0x80, 0x82, 0x19, 0x61, 0x71, 0x99, 0xaa,
    0xf8, 0x59, 0xfd, 0xde, 0xa0, 0x03, 0xa8, 0xab,
    0x9a, 0xec, 0x28, 0xac, 0x63, 0x79, 0x75, 0x84,
    0x03, 0xac, 0x45, 0x5e, 0x04, 0x15, 0xb3, 0x47,
    0xa2, 0x8f, 0x28, 0xb0, 0x72, 0xd0, 0x06, 0x02,
    0xaf, 0x1e, 0x0a, 0x0a, 0xe9, 0x11, 0x35, 0x4a,
    0x04, 0x42, 0xb5, 0x0f, 0xd2, 0xcf, 0x4d, 0xdf,
    0xdb, 0xef, 0x58, 0xbd, 0xf3, 0xa5, 0x3b, 0x11,
    0x3f, 0xc5, 0x47, 0x81, 0x85, 0xad, 0xd7, 0x1f,
    0x58, 0x06, 0x42, 0xdc, 0x37, 0x3c, 0xdb, 0x98,
    0x33, 0xa1, 0xc6, 0x80, 0x07, 0xe0, 0x2b, 0xc5,
    0xf5, 0x60, 0x35, 0x6a, 0xa2, 0x06, 0x40, 0x4a,
    0xac, 0x64, 0x02, 0x58, 0x4d, 0x07, 0xe3, 0x69,
    0xd7, 0xe0, 0x8f, 0xb5, 0xf4, 0xbc, 0xfa, 0xab,
    0x1a, 0xb0, 0xfa, 0x29, 0xf8, 0xca, 0xde, 0x78,
    0xf0, 0x89, 0xe2, 0xf9, 0xb7, 0x68, 0x5b, 0x0e,
    0xdc, 0x4e, 0x8a, 0x56, 0x8d, 0x33, 0x20, 0x2e,
    0xed, 0x2e, 0xab, 0x6f, 0xba, 0x77, 0xef, 0xe6,
    0x12, 0x62, 0x49, 0x9e, 0x87, 0x76, 0x1c, 0x1e,
    0xf4, 0x0e, 0x9e, 0x78, 0x98, 0x91, 0x1a, 0xe3,
    0xb4, 0x51, 0x4b, 0x8c, 0x2f, 0x08, 0x97, 0x8f,
    0xf9, 0x68, 0x61, 0x40, 0xcd, 0xb6, 0x10, 0xb4,
    0xfb, 0x75, 0xb4, 0x20, 0xc1, 0x5a, 0xda, 0x64,
    0xfd, 0x51, 0x06, 0x85, 0x9a, 0x9e, 0x5d, 0x82,
    0x14, 0xd4, 0x41, 0x4e, 0x75, 0x10, 0xb5, 0x7b,
    0xd0, 0x4c, 0xd1, 0x00, 0x01, 0x02, 0x81, 0x81,
    0x00, 0xcf, 0x8e, 0x68, 0x04, 0x67, 0x09, 0xa9,
    0x6e, 0xff, 0x11, 0x8c, 0xe5, 0xe4, 0x16, 0xdd,
    0xb6, 0xa6, 0x55, 0xca, 0x4b, 0x0b, 0xbb, 0xb7,
    0xf5, 0xe5, 0x73, 0xf3, 0x24, 0x84, 0x29, 0xb2,
    0xc3, 0xbc, 0x7f, 0x2b, 0x4a, 0xc7, 0xdf, 0x46,
    0x8e, 0xe1, 0x35, 0x69, 0x1b, 0x8e, 0x9f, 0x6b,
    0x4d, 0xf3, 0x65, 0xae, 0x3d, 0x87, 0x2b, 0xc9,
    0xf0, 0x8c, 0xf2, 0x88, 0x2f, 0x1b, 0x79, 0x80,
    0xd2, 0xb2, 0x64, 0x0a, 0xcc, 0x66, 0x69, 0x4c,
    0xa1, 0x85, 0xc4, 0x6a, 0x94, 0x46, 0x70, 0x69,
    0xbc, 0x8c, 0x1c, 0x62, 0x65, 0x4d, 0x68, 0xcc,
    0xe3, 0x3c, 0x6c, 0xe7, 0xd1, 0x09, 0xed, 0xdd,
    0x42, 0x10, 0x11, 0x6b, 0xdd, 0x7c, 0xe3, 0xe1,
    0x3b, 0x3b, 0x0d, 0x01, 0x6d, 0xca, 0x2f, 0x4b,
    0x45, 0x5e, 0x76, 0x5d, 0x5c, 0x6f, 0x53, 0xa4,
    0x38, 0x74, 0x75, 0x94, 0x2c, 0xda, 0xf8, 0xa6,
    0x01, 0x02, 0x81, 0x81, 0x00, 0xcd, 0x5f, 0x9d,
    0x6c, 0x94, 0xf6, 0x44, 0x37, 0x72, 0xfe, 0xcf,
    0xbe, 0x82, 0x96, 0x24, 0x22, 0x12, 0x07, 0x6f,
    0xd1, 0x57, 0x7b, 0xc7, 0x63, 0x20, 0xf5, 0x93,
    0x79, 0x70, 0x0b, 0xe4, 0x38, 0x19, 0x62, 0x7b,
    0x89, 0x3e, 0x45, 0xdf, 0xd6, 0xae, 0x9d, 0x0d,
    0xa8, 0x76, 0xc1, 0xbd, 0x04, 0x2b, 0xaa, 0x30,
    0x6a, 0xac, 0x65, 0x91, 0x61, 0xf0, 0xf8, 0x5d,
    0xa3, 0x53, 0xa4, 0xfb, 0x99, 0xac, 0x46, 0x7a,
    0x12, 0x4b, 0xf7, 0xa7, 0x48, 0x41, 0x61, 0x48,
    0x26, 0x5c, 0x68, 0x2f, 0x73, 0x91, 0xe4, 0x74,
    0xcd, 0xc9, 0x8b, 0xe7, 0x26, 0xe4, 0x35, 0xde,
    0x32, 0x6b, 0x24, 0x49, 0xf2, 0x04, 0x67, 0x3d,
    0x31, 0x8f, 0x22, 0xe5, 0x49, 0xae, 0x49, 0x94,
    0xb3, 0x45, 0x2b, 0xed, 0x6f, 0x9c, 0xc7, 0x80,
    0xf0, 0x42, 0xd5, 0x8f, 0x27, 0xd6, 0xd6, 0x49,
    0xf2, 0x16, 0xcc, 0x4b, 0x39, 0x02, 0x81, 0x81,
    0x00, 0xbb, 0xb7, 0xd7, 0x59, 0xcb, 0xfb, 0x10,
    0x13, 0xc4, 0x7b, 0x92, 0x0c, 0x45, 0xcb, 0x6c,
    0x81, 0x0a, 0x55, 0x63, 0x1d, 0x96, 0xa2, 0x13,
    0xd2, 0x40, 0xd1, 0x2a, 0xa1, 0xe7, 0x2a, 0x73,
    0x74, 0xd6, 0x61, 0xc9, 0xbc, 0xdb, 0xa2, 0x93,
    0x85, 0x1c, 0x28, 0x9b, 0x44, 0x82, 0x2c, 0xaa,
    0xf7, 0x18, 0x60, 0xe9, 0x42, 0xda, 0xa2, 0xff,
    0x04, 0x21, 0xe6, 0x24, 0xc7, 0x3e, 0x39, 0x19,
    0x0a, 0xf6, 0xae, 0xc6, 0x99, 0x71, 0x32, 0x61,
    0x4d, 0x60, 0xd7, 0x71, 0x71, 0x63, 0x77, 0xbe,
    0x19, 0xfa, 0x3a, 0x9d, 0xbf, 0x73, 0x50, 0x8a,
    0xa6, 0x26, 0x7b, 0x74, 0xfa, 0x39, 0xd9, 0xb9,
    0x18, 0x4b, 0xc2, 0x05, 0xe5, 0x8f, 0x53, 0xe6,
    0xdc, 0x14, 0x1f, 0x42, 0x20, 0x93, 0x11, 0x4d,
    0x29, 0x93, 0x32, 0xc8, 0x63, 0x96, 0x88, 0x76,
    0x69, 0x5c, 0xe3, 0x0e, 0xbd, 0xb6, 0xd9, 0xd6,
    0x01, 0x02, 0x81, 0x80, 0x62, 0xa2, 0xed, 0x84,
    0xdc, 0xf6, 0x7a, 0x44, 0xf7, 0x62, 0x12, 0x7c,
    0xb9, 0x53, 0x4a, 0xff, 0x62, 0x11, 0x58, 0x4e,
    0xfe, 0xe9, 0x60, 0x15, 0xe8, 0x1a, 0x8a, 0x3d,
    0xe4, 0xe6, 0x91, 0x31, 0xb0, 0x5f, 0x70, 0x5d,
    0xb6, 0x1e, 0xf1, 0x26, 0xb6, 0xae, 0x8f, 0x84,
    0xbd, 0xa4, 0xc7, 0x17, 0x5d, 0xb1, 0x5b, 0x97,
    0xa0, 0x3d, 0x17, 0xda, 0x26, 0x55, 0xe3, 0x03,
    0x32, 0x85, 0x26, 0xa1, 0xe3, 0xef, 0xe5, 0x69,
    0x2c, 0x3b, 0x41, 0x88, 0x9e, 0x7e, 0x0e, 0x9c,
    0xfd, 0xfc, 0xbb, 0xed, 0x91, 0xc0, 0x5b, 0xa9,
    0x0a, 0x87, 0xba, 0xf9, 0x1e, 0xda, 0x10, 0x61,
    0xbe, 0xbb, 0xab, 0x18, 0x25, 0xad, 0x3f, 0xe2,
    0xb1, 0x90, 0x5c, 0xf7, 0x4a, 0x51, 0xe4, 0xad,
    0x45, 0x27, 0x97, 0xdd, 0xe7, 0x3a, 0x9a, 0x5e,
    0xca, 0x7a, 0xaf, 0x4a, 0xbf, 0x10, 0x24, 0x6b,
    0xb5, 0x2f, 0x61, 0x61, 0x02, 0x81, 0x81, 0x00,
    0x85, 0x7c, 0x78, 0xa5, 0x11, 0xdf, 0xc3, 0x6a,
    0x38, 0x48, 0xfa, 0x7e, 0x48, 0xf0, 0x5a, 0x58,
    0xe2, 0xc5, 0x83, 0x4e, 0x38, 0x3f, 0x4a, 0x2b,
    0x07, 0x57, 0x31, 0xe7, 0xbe, 0x50, 0xb1, 0xbb,
    0x24, 0xf3, 0x3d, 0x8b, 0x53, 0xb7, 0xd1, 0x47,
    0x72, 0x5e, 0xd5, 0xd6, 0x4c, 0xce, 0x2c, 0x46,
    0x61, 0x9a, 0xaa, 0xc3, 0x0e, 0xd4, 0x23, 0x2c,
    0xdd, 0xf5, 0xb7, 0xad, 0x38, 0x52, 0x17, 0xc4,
    0x16, 0xbb, 0xda, 0x1c, 0x61, 0xb1, 0xca, 0x8d,
    0xb2, 0xa0, 0xbe, 0x4f, 0x3d, 0x19, 0x0e, 0xe0,
    0x0e, 0x52, 0xad, 0xf3, 0xaf, 0xd9, 0xcc, 0x78,
    0xc2, 0xb1, 0x5e, 0x05, 0x5e, 0xf2, 0x27, 0x84,
    0x15, 0xe4, 0x8f, 0xca, 0xc5, 0x92, 0x43, 0xe0,
    0x24, 0x8d, 0xf2, 0x5d, 0x55, 0xcc, 0x9d, 0x2f,
    0xa9, 0xf6, 0x9b, 0x67, 0x6a, 0x87, 0x74, 0x36,
    0x34, 0x7c, 0xd4, 0x9d, 0xff, 0xad, 0xee, 0x69
};

static void test_key_proxy_identity(void) {
    id certificate = CFBridgingRelease(SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)[NSData dataWithBytes:_c1 length:sizeof(_c1)]));
    isnt(certificate, nil, "created certificate");
    NSError *error;
    id key = CFBridgingRelease(SecKeyCreateWithData((CFDataRef)[NSData dataWithBytes:_k1 length:sizeof(_k1)], (CFDictionaryRef)@{(id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA, (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate}, (void *)&error));
    isnt(key, nil, "create key: %@", error);
    id identity = CFBridgingRelease(SecIdentityCreate(kCFAllocatorDefault, (__bridge SecCertificateRef)certificate, (__bridge SecKeyRef)key));
    isnt(identity, nil, "create identity");

    SecKeyProxy *identityProxy = [[SecKeyProxy alloc] initWithIdentity:(SecIdentityRef)identity];
    isnt(identityProxy, nil, "create identity proxy");

    id localIdentity = CFBridgingRelease([SecKeyProxy createIdentityFromEndpoint:identityProxy.endpoint error:&error]);
    isnt(localIdentity, nil, "create remote identity");

    id localKey;
    id localCertificate;
    SecIdentityCopyPrivateKey((__bridge SecIdentityRef)identity, (void *)&localKey);
    SecIdentityCopyCertificate((__bridge SecIdentityRef)identity, (void *)&localCertificate);
    isnt(localKey, nil, "got key from localIdentity");
    isnt(localCertificate, nil, "got certificate from localIdentity");

    ok([certificate isEqual:localCertificate], "Certificates are the same");
    is(SecKeyGetBlockSize((SecKeyRef)key), SecKeyGetBlockSize((SecKeyRef)localKey), "Keys are the same");

    // Check that it is not possible to get identity from key proxy
    SecKeyProxy *keyProxy = [[SecKeyProxy alloc] initWithKey:(SecKeyRef)key];
    error = nil;
    id secondIdentity = CFBridgingRelease([SecKeyProxy createIdentityFromEndpoint:keyProxy.endpoint error:&error]);
    is(secondIdentity, nil, "connecting identity to key proxy should not be possible.");
}
static const int TestKeyProxyIdentityCount = 10;

static const int TestCount =
TestKeyProxyConnectCount +
TestKeyProxySimpleOpsCount +
TestKeyCryptoOpsRSACount +
TestKeyCryptoOpsECCount +
TestKeyProxyConnectionHandlersCount +
TestKeyProxyIdentityCount;

int si_44_seckey_proxy(int argc, char *const *argv) {
    plan_tests(TestCount);
    
    @autoreleasepool {
        test_key_proxy_connect();
        test_key_proxy_simple_ops();
        test_key_proxy_crypto_ops_RSA();
        test_key_proxy_crypto_ops_EC();
        test_key_proxy_connection_handlers();
        test_key_proxy_identity();
    }

    return 0;
}
