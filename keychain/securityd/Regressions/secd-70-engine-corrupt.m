/*
 * Copyright (c) 2014 Apple Inc. All Rights Reserved.
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


// Test syncing between SecItemDataSource and SOSTestDataSource

#include "keychain/SecureObjectSync/Regressions/SOSTestDevice.h"
#include "keychain/SecureObjectSync/Regressions/SOSTestDataSource.h"
#include "secd_regressions.h"
#include "SecdTestKeychainUtilities.h"

#include "keychain/SecureObjectSync/SOSDigestVector.h"
#include "keychain/SecureObjectSync/SOSEngine.h"
#include "keychain/SecureObjectSync/SOSPeer.h"
#import "keychain/SecureObjectSync/SOSChangeTracker.h"
#include <Security/SecBase64.h>
#include <Security/SecItem.h>
#include <Security/SecItemPriv.h>
#include <corecrypto/ccsha2.h>
#include "keychain/securityd/SecItemServer.h"
#include "keychain/securityd/SecItemDataSource.h"
#include <utilities/SecCFWrappers.h>
#include <utilities/SecIOFormat.h>
#include <utilities/SecFileLocations.h>
#include "SOSAccountTesting.h"

#include <AssertMacros.h>
#include <stdint.h>
#if SOS_ENABLED

static int kTestTestCount = 121;

static void nosha1(void) {
    __block int iteration = 0;
    __block CFErrorRef error = NULL;
    SOSTestDeviceListTestSync("nosha1", test_directive, test_reason, 0, true, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest) {
        iteration++;
        // Add 10 items in first 10 sync messages
        if (iteration <= 6) {
            CFStringRef account = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("item%d"), iteration);
            SOSTestDeviceAddGenericItem(source, account, CFSTR("nosha1"));
            CFReleaseSafe(account);
            // Corrupt the 4th item added
            if (iteration == 4) {
                ok(SecDbPerformWrite(source->db, &error, ^(SecDbConnectionRef dbconn) {
                    ok(SecDbTransaction(dbconn, kSecDbExclusiveTransactionType, &error, ^(bool *commit) {
                        ok(SecDbExec(dbconn, CFSTR("UPDATE genp SET sha1=X'0000000000000000000000000000000000000000' WHERE rowid=5;"), &error),
                           "Corrupting rowid 5 by zeroing sha1: %@", error);
                        CFReleaseNull(error);
                    }), "SecDbTransaction: %@", error);
                    CFReleaseNull(error);
                }), "SecDbPerformWrite: %@", error);
                CFReleaseNull(error);
                return true;
            }
            return true;
        }


        return false;
    }, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest, SOSMessageRef message) {
        return false;
    }, CFSTR("Bad"), CFSTR("Good"), NULL);
}

static void drop_item(void) {
    __block int iteration = 0;
    __block CFErrorRef error = NULL;
    SOSTestDeviceListTestSync("drop_item", test_directive, test_reason, 0, true, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest) {
        iteration++;
        // Add 10 items in first 10 sync messages
        if (iteration <= 6) {
            CFStringRef account = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("item%d"), iteration);
            SOSTestDeviceAddGenericItem(source, account, CFSTR("drop_item"));
            CFReleaseSafe(account);
            // Corrupt the 4th item added
            if (iteration == 4) {
                ok(SecDbPerformWrite(source->db, &error, ^(SecDbConnectionRef dbconn) {
                    ok(SecDbTransaction(dbconn, kSecDbExclusiveTransactionType, &error, ^(bool *commit) {
                        ok(SecDbExec(dbconn, CFSTR("DELETE FROM genp WHERE rowid=5;"), &error),
                           "Corrupting rowid 5 by deleting object: %@", error);
                        CFReleaseNull(error);
                    }), "SecDbTransaction: %@", error);
                    CFReleaseNull(error);
                }), "SecDbPerformWrite: %@", error);
                CFReleaseNull(error);
                return true;
            }
            return true;
        }


        return false;
    }, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest, SOSMessageRef message) {
        return false;
    }, CFSTR("Abegail"), CFSTR("Billy"), NULL);
}

static void drop_manifest(void) {
    __block int iteration = 0;
    SOSTestDeviceListTestSync("drop_manifest", test_directive, test_reason, 0, true, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest) {
        iteration++;
        // Add 5 items on Alice and 4 on Bob in first 9 sync messages
        if (iteration <= 9) {
            CFStringRef account = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("item%d"), iteration / 2);
            SOSTestDeviceAddGenericItem(source, account, CFSTR("drop_manifest"));
            CFReleaseSafe(account);
            // Corrupt the manifest after 4th item added
            if (iteration == 4) {
                SOSEngineRef engine = SOSDataSourceGetSharedEngine(source->ds, NULL);
                SOSPeerRef peer = SOSEngineCopyPeerWithID(engine, SOSTestDeviceGetID(dest), NULL);
                SOSManifestRef mf = SOSEngineCopyLocalPeerManifest(engine, peer, NULL);
                CFReleaseNull(peer);
                CFMutableArrayRef changes = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
                SOSManifestForEach(mf, ^(CFDataRef e, bool *stop) {
                    SOSChangesAppendDelete(changes, e);
                });
                ok(SOSEngineUpdateChanges(engine, kSOSDataSourceSOSTransaction, changes, NULL), "droped manifest from %@", source);
                CFReleaseNull(changes);
                CFReleaseNull(mf);
                return true;
            }
            return true;
        }

        return false;
    }, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest, SOSMessageRef message) {
        return false;
    }, CFSTR("Ann"), CFSTR("Ben"), NULL);
}

static void add_sha1(void) {
    TODO: {
        //todo("this never stops syncing");
        __block int iteration = 0;
        __block CFErrorRef error = NULL;
        SOSTestDeviceListTestSync("add_sha1", test_directive, test_reason, 0, true, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest) {
            iteration++;
            // Add 9 items in first 9 sync messages
            if (iteration <= 9) {
                CFStringRef account = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("item%d"), iteration);
                SOSTestDeviceAddGenericItem(source, account, CFSTR("add_sha1"));
                CFReleaseSafe(account);
                // Corrupt the manifest after 4th item added
                if (iteration == 4) {
                    ok(SecDbPerformWrite(source->db, &error, ^(SecDbConnectionRef dbconn) {
                        ok(SecDbTransaction(dbconn, kSecDbExclusiveTransactionType, &error, ^(bool *commit) {
                            ok(SecDbExec(dbconn, CFSTR("UPDATE genp SET sha1=X'0000000000000000000000000000000000000000' WHERE rowid=5;"), &error),
                               "Corrupting rowid 5 by zeroing sha1: %@", error);
                            CFReleaseNull(error);
                        }), "SecDbTransaction: %@", error);
                        CFReleaseNull(error);
                    }), "SecDbPerformWrite: %@", error);
                    CFReleaseNull(error);

                    SOSEngineRef engine = SOSDataSourceGetSharedEngine(source->ds, NULL);
                    uint8_t zeroDigest[20] = {};
                    CFDataRef zDigest = CFDataCreate(kCFAllocatorDefault, zeroDigest, 20);
                    CFMutableArrayRef changes = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
                    SOSChangesAppendAdd(changes, zDigest);
                    ok(SOSEngineUpdateChanges(engine, kSOSDataSourceSOSTransaction, changes, NULL), "corrupting manifest");
                    CFReleaseSafe(zDigest);
                    CFReleaseNull(changes);
                    return true;
                }
                return true;
            }

            return false;
        }, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest, SOSMessageRef message) {
            return false;
        }, CFSTR("Andy"), CFSTR("Bill"), NULL);
    }
}

static void change_sha1(void) {
TODO: {
    //todo("this never stops syncing");
    __block int iteration = 0;
    __block CFErrorRef error = NULL;
    SOSTestDeviceListTestSync("change_sha1", test_directive, test_reason, 0, true, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest) {
        iteration++;
        // Add 9 items in first 9 sync messages
        if (iteration <= 9) {
            CFStringRef account = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("item%d"), iteration);
            CFStringRef server = CFSTR("change_sha1");
            // Corrupt the manifest after 4th item added
            if (!SOSDataSourceWithAPI(source->ds, true, &error, ^(SOSTransactionRef txn, bool *commit) {
                SOSObjectRef object = SOSDataSourceCreateGenericItem(source->ds, account, server);
                ok(SOSDataSourceMergeObject(source->ds, txn, object, NULL, &error), "%@ added API object %@", SOSTestDeviceGetID(source), error ? (CFTypeRef)error : (CFTypeRef)CFSTR("ok"));
                if (iteration == 3) {
                    sqlite_int64 rowid = SecDbItemGetRowId((SecDbItemRef)object, NULL);
                    CFStringRef sql = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("UPDATE genp SET sha1=X'0000000000000000000000000000000000000000' WHERE rowid=%lld;"), rowid);
                    ok(SecDbExec((SecDbConnectionRef)txn, sql, &error),
                       "Corrupting rowid %lld by zeroing sha1: %@", rowid, error);
                    CFReleaseNull(sql);
                    SOSEngineRef engine = SOSDataSourceGetSharedEngine(source->ds, NULL);
                    CFMutableArrayRef changes = CFArrayCreateMutableForCFTypes(kCFAllocatorDefault);
                    uint8_t zeroDigest[20] = {};
                    CFDataRef zDigest = CFDataCreate(kCFAllocatorDefault, zeroDigest, 20);
                    SOSChangesAppendAdd(changes, zDigest);
                    CFDataRef digest = SOSObjectCopyDigest(source->ds, object, NULL);
                    SOSChangesAppendDelete(changes, digest);
                    const uint8_t *d = CFDataGetBytePtr(digest);
                    ok(SOSEngineUpdateChanges(engine, kSOSDataSourceSOSTransaction, changes, NULL), "corrupting manifest %lld %02X%02x%02x%02x",
                       rowid, d[0], d[1], d[2], d[3]);
                    CFReleaseSafe(zDigest);
                    CFReleaseSafe(digest);
                    CFReleaseNull(changes);
                }
                CFReleaseSafe(object);
                CFReleaseNull(error);
            }))
                fail("ds transaction %@", error);
            CFReleaseNull(error);
            CFReleaseNull(account);
            return true;
        }
        return false;
    }, ^bool(SOSTestDeviceRef source, SOSTestDeviceRef dest, SOSMessageRef message) {
        if (iteration >= 3)
            pass("%@", source);
        return false;
    }, CFSTR("Alice"), CFSTR("Bob"), NULL);
}
}
#endif

int secd_70_engine_corrupt(int argc, char *const *argv)
{
#if SOS_ENABLED
    plan_tests(kTestTestCount);
    enableSOSCompatibilityForTests();
    __security_simulatecrash_enable(false);
    /* custom keychain dir */
    secd_test_setup_temp_keychain(__FUNCTION__, NULL);
    nosha1();
    drop_item();
    drop_manifest();
    add_sha1();
    change_sha1();
    secd_test_teardown_delete_temp_keychain(__FUNCTION__);
    __security_simulatecrash_enable(true);
#else
    plan_tests(0);
#endif
    return 0;
}
