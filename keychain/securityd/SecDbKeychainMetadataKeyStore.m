/*
 * Copyright (c) 2018 Apple Inc. All Rights Reserved.
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

#import "SecDbKeychainMetadataKeyStore.h"
#import <dispatch/dispatch.h>
#import <utilities/SecAKSWrappers.h>
#import <notify.h>
#import "SecItemServer.h"
#import "SecAKSObjCWrappers.h"
#import "SecDbKeychainSerializedMetadataKey.h"
#include "SecItemDb.h"  // kc_transaction
#import "sec_action.h"

NS_ASSUME_NONNULL_BEGIN

static SecDbKeychainMetadataKeyStore*_Nullable sharedStore = nil;
static dispatch_queue_t sharedMetadataStoreQueue;
static void initializeSharedMetadataStoreQueue(void) {
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedMetadataStoreQueue = dispatch_queue_create("metadata_store", DISPATCH_QUEUE_SERIAL);
    });
}

@interface SecDbKeychainMetadataKeyStore ()
@property dispatch_queue_t queue;
@property NSMutableDictionary* keysDict;
@property int keybagNotificationToken;
@end

@implementation SecDbKeychainMetadataKeyStore

+ (void)resetSharedStore
{
    initializeSharedMetadataStoreQueue();
    dispatch_sync(sharedMetadataStoreQueue, ^{
        if(sharedStore) {
            [sharedStore dropAllKeys];
        }
        sharedStore = nil;
    });
}

+ (instancetype)sharedStore
{
    __block SecDbKeychainMetadataKeyStore* ret;
    initializeSharedMetadataStoreQueue();
    dispatch_sync(sharedMetadataStoreQueue, ^{
        if(!sharedStore) {
            sharedStore = [[self alloc] _init];
        }

        ret = sharedStore;
    });

    return ret;
}

+ (bool)cachingEnabled
{
    return true;
}

- (instancetype)_init
{
    if (self = [super init]) {
        _keysDict = [[NSMutableDictionary alloc] init];
        _queue = dispatch_queue_create("SecDbKeychainMetadataKeyStore", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
        _keybagNotificationToken = NOTIFY_TOKEN_INVALID;

        __weak __typeof(self) weakSelf = self;
        notify_register_dispatch(kUserKeybagStateChangeNotification, &_keybagNotificationToken, _queue, ^(int inToken) {
            bool locked = true;
            CFErrorRef error = NULL;
            if (!SecAKSGetIsLocked(g_keychain_keybag, &locked, &error)) {
                secerror("SecDbKeychainMetadataKeyStore: error getting lock state: %@", error);
                CFReleaseNull(error);
            }

            if (locked) {
                [weakSelf _onQueueDropClassAKeys];
            }
        });
    }

    return self;
}

- (void)dealloc {
    if (_keybagNotificationToken != NOTIFY_TOKEN_INVALID) {
        notify_cancel(_keybagNotificationToken);
        _keybagNotificationToken = NOTIFY_TOKEN_INVALID;
    }
}

- (void)dropClassAKeys
{
    dispatch_sync(_queue, ^{
        [self _onQueueDropClassAKeys];
    });
}

- (void)_onQueueDropClassAKeys
{
    dispatch_assert_queue(_queue);

    secnotice("SecDbKeychainMetadataKeyStore", "dropping class A metadata keys");
    _keysDict[@(key_class_ak)] = nil;
    _keysDict[@(key_class_aku)] = nil;
    _keysDict[@(key_class_akpu)] = nil;
}

- (void)dropAllKeys
{
    dispatch_sync(_queue, ^{
        [self _onQueueDropAllKeys];
    });
}

- (void)_onQueueDropAllKeys
{
    dispatch_assert_queue(_queue);

    secnotice("SecDbKeychainMetadataKeyStore", "dropping all metadata keys");
    [_keysDict removeAllObjects];
}

// Return SFAESKey and actual keyclass if NSData decrypts, or nil if it does not and populate error
- (SFAESKey* _Nullable)validateWrappedKey:(NSData*)wrapped
                              forKeyClass:(keyclass_t)keyclass
                           actualKeyClass:(keyclass_t*)outKeyclass
                                   keybag:(keybag_handle_t)keybag
                             keySpecifier:(SFAESKeySpecifier*)specifier
                                    error:(NSError**)error
{
    keyclass_t classToUse = keyclass;
    if (*outKeyclass != key_class_none && *outKeyclass != keyclass) {
        classToUse = *outKeyclass;
    }

    NSMutableData* unwrapped = [NSMutableData dataWithLength:APPLE_KEYSTORE_MAX_KEY_LEN];
    SFAESKey* key = NULL;
    NSError *localError = nil;
    if ([SecAKSObjCWrappers aksDecryptWithKeybag:keybag keyclass:classToUse ciphertext:wrapped outKeyclass:NULL plaintext:unwrapped personaId:NULL personaIdLength:0 error:&localError]) {
        key = [[SFAESKey alloc] initWithData:unwrapped specifier:specifier error:&localError];
        if (!key) {
            secerror("SecDbKeychainItemV7: AKS decrypted metadata blob for class %d but could not turn it into a key: %@", classToUse, localError);
        }
    }
#if USE_KEYSTORE
    else if (classToUse < key_class_last && *outKeyclass == key_class_none) {
        *outKeyclass = classToUse | (key_class_last + 1);
        if ([SecAKSObjCWrappers aksDecryptWithKeybag:keybag keyclass:*outKeyclass ciphertext:wrapped outKeyclass:NULL plaintext:unwrapped personaId:NULL personaIdLength:0 error:&localError]) {
            key = [[SFAESKey alloc] initWithData:unwrapped specifier:specifier error:&localError];
        }
    }
#endif
    if (!key) {
        // Don't be noisy for mundane error
        if (!([localError.domain isEqualToString:(__bridge NSString*)kSecErrorDomain] && localError.code == errSecInteractionNotAllowed)) {
            secerror("SecDbKeychainItemV7: Unable to create key from retrieved data: %@", localError);
        }
        if (error) {
            *error = localError;
        }
    }

    return key;
}

- (SFAESKey* _Nullable)newKeyForKeyclass:(keyclass_t)keyclass
                              withKeybag:(keybag_handle_t)keybag
                            keySpecifier:(SFAESKeySpecifier*)specifier
                                database:(SecDbConnectionRef)dbt
                                   error:(NSError**)error
{
    NSError *localError = nil;
    SFAESKey* key = [[SFAESKey alloc] initRandomKeyWithSpecifier:specifier error:&localError];
    if (!key) {
        if (error) {
            *error = localError;
        }
        return nil;
    }
    return [self writeKey:key ForKeyclass:keyclass withKeybag:keybag keySpecifier:specifier database:dbt error:error];
}

- (SFAESKey* _Nullable)writeKey:(SFAESKey*)key
                    ForKeyclass:(keyclass_t)keyclass
                     withKeybag:(keybag_handle_t)keybag
                   keySpecifier:(SFAESKeySpecifier*)specifier
                       database:(SecDbConnectionRef)dbt
                          error:(NSError**)error
{
    NSError *localError = nil;
    dispatch_assert_queue(_queue);

    NSMutableData* wrappedKey = [NSMutableData dataWithLength:AKS_WRAP_KEY_MAX_WRAPPED_KEY_LEN];
    keyclass_t outKeyclass = keyclass;

    if (![SecAKSObjCWrappers aksEncryptWithKeybag:keybag keyclass:keyclass plaintext:key.keyData outKeyclass:&outKeyclass ciphertext:wrappedKey personaId:NULL personaIdLength:0 error:&localError]) {
        secerror("SecDbMetadataKeyStore: Unable to encrypt new metadata key to keybag: %@", localError);
        if (error) {
            *error = localError;
        }
        return nil;
    }

    __block bool ok = true;
    __block CFErrorRef cfErr = NULL;
    NSString* sql = @"INSERT OR REPLACE INTO metadatakeys (keyclass, actualKeyclass, data) VALUES (?,?,?)";
    ok &= SecDbPrepare(dbt, (__bridge CFStringRef)sql, &cfErr, ^(sqlite3_stmt *stmt) {
        ok &= SecDbBindObject(stmt, 1, (__bridge CFNumberRef)@(keyclass), &cfErr);
        ok &= SecDbBindObject(stmt, 2, (__bridge CFNumberRef)@(outKeyclass), &cfErr);
        ok &= SecDbBindBlob(stmt, 3, wrappedKey.bytes, wrappedKey.length, SQLITE_TRANSIENT, &cfErr);
        ok &= SecDbStep(dbt, stmt, &cfErr, NULL);
    });

    if (!ok) {
        secerror("Failed to write new metadata key for %d: %@", keyclass, cfErr);
        BridgeCFErrorToNSErrorOut(error, cfErr);
        return nil;
    }

    return key;
}

- (BOOL)readKeyDataForClass:(keyclass_t)keyclass
                     fromDb:(SecDbConnectionRef)dbt
             actualKeyclass:(keyclass_t*)actualKeyclass
                 wrappedKey:(NSData**)outWrappedKey
                      error:(NSError**)error
{
    dispatch_assert_queue(_queue);

    NSString* sql = @"SELECT data, actualKeyclass FROM metadatakeys WHERE keyclass = ?";

    __block NSData* wrappedKey;
    __block bool ok = true;
    __block bool found = false;
    __block CFErrorRef cfError = NULL;
    ok &= SecDbPrepare(dbt, (__bridge CFStringRef)sql, &cfError, ^(sqlite3_stmt *stmt) {
        ok &= SecDbBindObject(stmt, 1, (__bridge CFNumberRef)@(keyclass), &cfError);
        ok &= SecDbStep(dbt, stmt, &cfError, ^(bool *stop) {
            wrappedKey = [[NSData alloc] initWithBytes:sqlite3_column_blob(stmt, 0) length:sqlite3_column_bytes(stmt, 0)];
            *actualKeyclass = sqlite3_column_int(stmt, 1);
            found = true;
        });
    });

    // ok && !found means no error is passed back, which is specifically handled in keyForKeyclass
    if (!ok || !found) {
        BridgeCFErrorToNSErrorOut(error, cfError);
        *actualKeyclass = key_class_none;
        return NO;
    }

    *outWrappedKey = wrappedKey;
    return YES;
}

- (SFAESKey* _Nullable)fetchKeyForClass:(keyclass_t)keyclass
                       fromDb:(SecDbConnectionRef)dbt
                       keybag:(keybag_handle_t)keybag
                    specifier:(SFAESKeySpecifier*)keySpecifier
                  allowWrites:(BOOL)allowWrites
                        error:(NSError**)error
{
    dispatch_assert_queue(_queue);

    NSData* wrappedKey;
    keyclass_t actualKeyClass = key_class_none;
    if (![self readKeyDataForClass:keyclass fromDb:dbt actualKeyclass:&actualKeyClass wrappedKey:&wrappedKey error:error]) {
        return nil;
    }

    SFAESKey* key;
    keyclass_t classFromDisk = key_class_none;
    if (wrappedKey.length > 0) {
        classFromDisk = actualKeyClass;
        key = [self validateWrappedKey:wrappedKey forKeyClass:keyclass actualKeyClass:&actualKeyClass keybag:keybag keySpecifier:keySpecifier error:error];
        if (!key) {
            return nil;
        }

    } else {                    // Wait, there's a row for this class but not something which might be a key?
        secnotice("SecDbMetadataKeyStore", "No metadata key found on disk despite existing row. That's odd.");
        return nil;
    }

    if (allowWrites && classFromDisk != actualKeyClass) {
        NSError* localError;
        if (![self writeKey:key ForKeyclass:keyclass withKeybag:keybag keySpecifier:keySpecifier database:dbt error:&localError]) {
            // if this fails we can try again in future
            secwarning("SecDbMetadataKeyStore: Unable to rewrite metadata key for %d to new format: %@", keyclass, localError);
            localError = nil;
        }
    }

    return key;
}

- (SFAESKey* _Nullable)keyForKeyclass:(keyclass_t)keyclass
                     keybag:(keybag_handle_t)keybag
               keySpecifier:(SFAESKeySpecifier*)keySpecifier
                allowWrites:(BOOL)allowWrites
                      error:(NSError**)error
{
    if (!error) {
        secerror("keyForKeyclass called without error param, this is a bug");
        return nil;
    }

    static __thread BOOL reentrant = NO;
    NSAssert(!reentrant, @"re-entering -[%@ %@] - that shouldn't happen!", NSStringFromClass(self.class), NSStringFromSelector(_cmd));
    reentrant = YES;

    keyclass = SecAKSSanitizedKeyclass(keyclass);

    __block SFAESKey* key = nil;
    __block NSError* nsErrorLocal = nil;
    __block CFErrorRef cfError = NULL;
    __block bool ok = true;
    dispatch_sync(_queue, ^{
        // try our cache first and rejoice if that succeeds
        bool allowCaching = [SecDbKeychainMetadataKeyStore cachingEnabled];

        key = allowCaching ? self->_keysDict[@(keyclass)] : nil;
        if (key) {
            return;     // Cache contains validated key for class, excellent!
        }

        // Key not in cache. Open a transaction to find or optionally (re)create key. Transactions can be nested, so this is fine.
        ok &= kc_with_dbt_non_item_tables(true, NULL, &cfError, ^bool(SecDbConnectionRef dbt) {
            key = [self fetchKeyForClass:keyclass
                                  fromDb:dbt
                                  keybag:keybag
                               specifier:keySpecifier
                             allowWrites:allowWrites
                                   error:&nsErrorLocal];

            // The code for this conditional is a little convoluted because I want the "keychain locked" message to take precedence over the "not allowed to create one" message.
            if (!key && ([nsErrorLocal.domain isEqualToString:(__bridge NSString*)kSecErrorDomain] && nsErrorLocal.code == errSecInteractionNotAllowed)) {
                static sec_action_t logKeychainLockedMessageAction;
                static dispatch_once_t keychainLockedMessageOnceToken;
                dispatch_once(&keychainLockedMessageOnceToken, ^{
                    logKeychainLockedMessageAction = sec_action_create("keychainlockedlogmessage", 1);
                    sec_action_set_handler(logKeychainLockedMessageAction, ^{
                        secerror("SecDbKeychainItemV7: cannot decrypt metadata key because the keychain is locked (%ld)", (long)nsErrorLocal.code);
                    });
                });
                sec_action_perform(logKeychainLockedMessageAction);
            } else if (!key && !allowWrites) {
                secwarning("SecDbMetadataKeyStore: Unable to load metadatakey for class %d from disk (%@) and not allowed to create new one", keyclass, nsErrorLocal);
                if (!nsErrorLocal) {
                    // If this is at creation time we are allowed to create so won't be here
                    // If this is at fetch time and we have a missing or bad key then the item /is/ dead
                    nsErrorLocal = [NSError errorWithDomain:(id)kSecErrorDomain code:errSecDecode userInfo:@{NSLocalizedDescriptionKey: @"Unable to find a suitable metadata key and not permitted to create one"}];
                }
                return false;
            // If this error is errSecDecode, then it's failed authentication and likely will forever. Other errors are scary. If !key and !error then no key existed.
            } else if ((!key && !nsErrorLocal) || (!key && [nsErrorLocal.domain isEqualToString:NSOSStatusErrorDomain] && nsErrorLocal.code == errSecDecode)) {
                secwarning("SecDbMetadataKeyStore: unable to use key (%ld), will attempt to create new one", (long)nsErrorLocal.code);
                nsErrorLocal = nil;
                key = [self newKeyForKeyclass:keyclass withKeybag:keybag keySpecifier:keySpecifier database:dbt error:&nsErrorLocal];
                if (!key) {
                    secerror("SecDbMetadataKeyStore: unable to create or save new key: %@", nsErrorLocal);
                    return false;
                }
            } else if (!key) {
                secerror("SecDbMetadataKeyStore: scary error encountered: %@", nsErrorLocal);
            } else if (allowCaching) {
                self->_keysDict[@(keyclass)] = key; // Only cache keys fetched from disk
            }
            return !!key;
        }); // kc_with_dbt
    }); // our queue

    if (!ok || !key) {
        if (nsErrorLocal) {
            *error = nsErrorLocal;
            CFReleaseNull(cfError);
        } else {
            BridgeCFErrorToNSErrorOut(error, cfError);
        }
        assert(*error); // Triggers only in testing, which is by design not to break production
        key = nil;
    }

    reentrant = NO;

    return key;
}

@end

NS_ASSUME_NONNULL_END
