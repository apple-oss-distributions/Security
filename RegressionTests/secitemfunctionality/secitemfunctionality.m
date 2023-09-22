//
//  Copyright 2016 Apple. All rights reserved.
//

#include <Foundation/Foundation.h>
#include <Security/Security.h>
#include <Security/SecItemPriv.h>
#include <Security/SecBasePriv.h>
#include <Security/SecIdentityPriv.h>
#include <mach/mach_time.h>
#include <err.h>
#include <strings.h>

#if SEC_OS_OSX_INCLUDES
#include <Security/SecKeychain.h>
#endif

static void
fail(const char *fmt, ...) __printflike(1, 2) __attribute__((noreturn));


static void
fail(const char *fmt, ...)
{
    va_list ap;
    printf("[FAIL]\n");
    fflush(stdout);

    va_start(ap, fmt);
    verrx(1, fmt, ap);
    va_end(ap);
}

static NSString *kAccessGroup1 = @"keychain-test-secitemfunctionality-1";
static NSString *kAccessGroup2 = @"keychain-test-secitemfunctionality-2";

#if 0
/*
 * Create item w/o data, try to make sure we end up in the OS X keychain
 */

static void
CheckItemAddDeleteMaybeLegacyKeychainNoData(void)
{
    OSStatus status;

    printf("[BEGIN] %s\n", __FUNCTION__);

    NSDictionary *query = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccount : @"item-delete-me",
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlock,
    };
    status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess && status != errSecItemNotFound)
        fail("cleanup item: %d", (int)status);

    /*
     * now check add notification
     */

    status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    if (status != errSecSuccess)
        fail("add item: %d: %s", (int)status, [[query description] UTF8String]);

    /*
     * clean up
     */

    status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess)
        fail("cleanup2 item: %d", (int)status);


    printf("[PASS] %s\n", __FUNCTION__);

}
#endif

static void
CheckItemAddDeleteNoData(void)
{
    OSStatus status;

    printf("[BEGIN] %s\n", __FUNCTION__);

    NSDictionary *query = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrAccount : @"item-delete-me",
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlock,
        (id)kSecUseDataProtectionKeychain: @YES,
    };
    status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess && status != errSecItemNotFound)
        fail("cleanup item: %d", (int)status);

    /*
     * Add item
     */

    status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    if (status != errSecSuccess)
        fail("add item: %d: %s", (int)status, [[query description] UTF8String]);

    /*
     * clean up
     */

    status = SecItemDelete((__bridge CFDictionaryRef)query);
    if (status != errSecSuccess)
        fail("cleanup2 item: %d", (int)status);

    printf("[PASS] %s\n", __FUNCTION__);
}

static void
CheckItemUpdateAccessGroupGENP(void)
{
    OSStatus status;

    printf("[BEGIN] %s\n", __FUNCTION__);

    NSDictionary *clean1 = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecUseDataProtectionKeychain: @YES,
    };
    NSDictionary *clean2 = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup2,
        (id)kSecUseDataProtectionKeychain: @YES,
    };

    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);
    (void)SecItemDelete((__bridge CFDictionaryRef)clean2);

    /*
     * Add item
     */

    NSDictionary *add = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrAccount : @"item-delete-me",
        (id)kSecUseDataProtectionKeychain : (id)kCFBooleanTrue,
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlock,
        (id)kSecUseDataProtectionKeychain: @YES,
    };
    status = SecItemAdd((__bridge CFDictionaryRef)add, NULL);
    if (status != errSecSuccess)
        fail("add item: %d: %s", (int)status, [[add description] UTF8String]);

    /*
     * Update access group
     */
    NSDictionary *query = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrAccount : @"item-delete-me",
        (id)kSecUseDataProtectionKeychain: @YES,
    };
    NSDictionary *modified = @{
        (id)kSecAttrAccessGroup : kAccessGroup2,
    };

    status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)modified);
    if (status != errSecSuccess)
        fail("cleanup2 item: %d", (int)status);

    /*
     *
     */
    NSDictionary *check1 = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrAccount : @"item-delete-me",
        (id)kSecUseDataProtectionKeychain: @YES,
    };
    status = SecItemCopyMatching((__bridge CFDictionaryRef)check1, NULL);
    if (status != errSecItemNotFound)
        fail("check1 item: %d", (int)status);


    NSDictionary *check2 = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccessGroup : kAccessGroup2,
        (id)kSecAttrAccount : @"item-delete-me",
        (id)kSecUseDataProtectionKeychain: @YES,
    };
    status = SecItemCopyMatching((__bridge CFDictionaryRef)check2, NULL);
    if (status != errSecSuccess)
        fail("check2 item: %d", (int)status);

    /*
     * Clean
     */
    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);
    (void)SecItemDelete((__bridge CFDictionaryRef)clean2);

    printf("[PASS] %s\n", __FUNCTION__);
}

static NSString *certDataBase64 = @"\
MIIEQjCCAyqgAwIBAgIJAJdFadWqNIfiMA0GCSqGSIb3DQEBBQUAMHMxCzAJBgNVBAYTAkNaMQ8wDQYD\
VQQHEwZQcmFndWUxFTATBgNVBAoTDENvc21vcywgSW5jLjEXMBUGA1UEAxMOc3VuLmNvc21vcy5nb2Qx\
IzAhBgkqhkiG9w0BCQEWFHRoaW5nQHN1bi5jb3Ntb3MuZ29kMB4XDTE2MDIyNjE0NTQ0OVoXDTE4MTEy\
MjE0NTQ0OVowczELMAkGA1UEBhMCQ1oxDzANBgNVBAcTBlByYWd1ZTEVMBMGA1UEChMMQ29zbW9zLCBJ\
bmMuMRcwFQYDVQQDEw5zdW4uY29zbW9zLmdvZDEjMCEGCSqGSIb3DQEJARYUdGhpbmdAc3VuLmNvc21v\
cy5nb2QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5u9gnYEDzQIVu7yC40VcXTZ01D9CJ\
oD/mH62tebEHEdfVPLWKeq+uAHnJ6fTIJQvksaISOxwiOosFjtI30mbe6LZ/oK22wYX+OUwKhAYjZQPy\
RYfuaJe/52F0zmfUSJ+KTbUZrXbVVFma4xPfpg4bptvtGkFJWnufvEEHimOGmO5O69lXA0Hit1yLU0/A\
MQrIMmZT8gb8LMZGPZearT90KhCbTHAxjcBfswZYeL8q3xuEVHXC7EMs6mq8IgZL7mzSBmrCfmBAIO0V\
jW2kvmy0NFxkjIeHUShtYb11oYYyfHuz+1vr1y6FIoLmDejKVnwfcuNb545m26o+z/m9Lv9bAgMBAAGj\
gdgwgdUwHQYDVR0OBBYEFGDdpPELS92xT+Hkh/7lcc+4G56VMIGlBgNVHSMEgZ0wgZqAFGDdpPELS92x\
T+Hkh/7lcc+4G56VoXekdTBzMQswCQYDVQQGEwJDWjEPMA0GA1UEBxMGUHJhZ3VlMRUwEwYDVQQKEwxD\
b3Ntb3MsIEluYy4xFzAVBgNVBAMTDnN1bi5jb3Ntb3MuZ29kMSMwIQYJKoZIhvcNAQkBFhR0aGluZ0Bz\
dW4uY29zbW9zLmdvZIIJAJdFadWqNIfiMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAFYi\
Zu/dfAMOrD51bYxP88Wu6iDGBe9nMG/0lkKgnX5JQKCxfxFMk875rfa+pljdUMOaPxegOXq1DrYmQB9O\
/pHI+t7ozuWHRj2zKkVgMWAygNWDPcoqBEus53BdAgA644aPN2JvnE4NEPCllOMKftPoIWbd/5ZjCx3a\
bCuxBdXq5YSmiEnOdGfKeXjeeEiIDgARb4tLgH5rkOpB1uH/ZCWn1hkiajBhrGhhPhpA0zbkZg2Ug+8g\
XPlx1yQB1VOJkj2Z8dUEXCaRRijInCJ2eU+pgJvwLV7mxmSED7DEJ+b+opxJKYrsdKBU6RmYpPrDa+KC\
/Yfu88P9hKKj0LmBiREA\
";

static NSString *keyDataBase64 = @"\
MIIEogIBAAKCAQEAubvYJ2BA80CFbu8guNFXF02dNQ/QiaA/5h+trXmxBxHX1Ty1inqvrgB5yen0yCUL\
5LGiEjscIjqLBY7SN9Jm3ui2f6CttsGF/jlMCoQGI2UD8kWH7miXv+dhdM5n1Eifik21Ga121VRZmuMT\
36YOG6bb7RpBSVp7n7xBB4pjhpjuTuvZVwNB4rdci1NPwDEKyDJmU/IG/CzGRj2Xmq0/dCoQm0xwMY3A\
X7MGWHi/Kt8bhFR1wuxDLOpqvCIGS+5s0gZqwn5gQCDtFY1tpL5stDRcZIyHh1EobWG9daGGMnx7s/tb\
69cuhSKC5g3oylZ8H3LjW+eOZtuqPs/5vS7/WwIDAQABAoIBAGcwmQAPdyZus3OVwa1NCUD2KyB+39KG\
yNmWwgx+br9Jx4s+RnJghVh8BS4MIKZOBtSRaEUOuCvAMNrupZbD+8leq34vDDRcQpCizr+M6Egj6FRj\
Ewl+7Mh+yeN2hbMoghL552MTv9D4Iyxteu4nuPDd/JQ3oQwbDFIL6mlBFtiBDUr9ndemmcJ0WKuzor6a\
3rgsygLs8SPyMefwIKjh5rJZls+iv3AyVEoBdCbHBz0HKgLVE9ZNmY/gWqda2dzAcJxxMdafeNVwHovv\
BtyyRGnA7Yikx2XT4WLgKfuUsYLnDWs4GdAa738uxPBfiddQNeRjN7jRT1GZIWCk0P29rMECgYEA8jWi\
g1Dph+4VlESPOffTEt1aCYQQWtHs13Qex95HrXX/L49fs6cOE7pvBh7nVzaKwBnPRh5+3bCPsPmRVb7h\
k/GreOriCjTZtyt2XGp8eIfstfirofB7c1lNBjT61BhgjJ8Moii5c2ksNIOOZnKtD53n47mf7hiarYkw\
xFEgU6ECgYEAxE8Js3gIPOBjsSw47XHuvsjP880nZZx/oiQ4IeJb/0rkoDMVJjU69WQu1HTNNAnMg4/u\
RXo31h+gDZOlE9t9vSXHdrn3at67KAVmoTbRknGxZ+8tYpRJpPj1hyufynBGcKwevv3eHJHnE5eDqbHx\
ynZFkXemzT9aMy3R4CCFMXsCgYAYyZpnG/m6WohE0zthMFaeoJ6dSLGvyboWVqDrzXjCbMf/4wllRlxv\
cm34T2NXjpJmlH2c7HQJVg9uiivwfYdyb5If3tHhP4VkdIM5dABnCWoVOWy/NvA7XtE+KF/fItuGqKRP\
WCGaiRHoEeqZ23SQm5VmvdF7OXNi/R5LiQ3o4QKBgAGX8qg2TTrRR33ksgGbbyi1UJrWC3/TqWWTjbEY\
uU51OS3jvEQ3ImdjjM3EtPW7LqHSxUhjGZjvYMk7bZefrIGgkOHx2IRRkotcn9ynKURbD+mcE249beuc\
6cFTJVTrXGcFvqomPWtV895A2JzECQZvt1ja88uuu/i2YoHDQdGJAoGAL2TEgiMXiunb6PzYMMKKa+mx\
mFnagF0Ek3UJ9ByXKoLz3HFEl7cADIkqyenXFsAER/ifMyCoZp/PDBd6ZkpqLTdH0jQ2Yo4SllLykoiZ\
fBWMfjRu4iw9E0MbPB3blmtzfv53BtWKy0LUOlN4juvpqryA7TgaUlZkfMT+T1TC7xU=\
";


static SecIdentityRef
CreateTestIdentity(void)
{
    NSData *certData = [[NSData alloc] initWithBase64EncodedString:certDataBase64 options:0];
    SecCertificateRef cert = SecCertificateCreateWithData(kCFAllocatorDefault, (CFDataRef)certData);
    if (cert == NULL)
        fail("create certificate from data");

    NSData *keyData = [[NSData alloc] initWithBase64EncodedString:keyDataBase64 options:0];
    NSDictionary *keyAttrs = @{
                               (id)kSecAttrKeyType: (id)kSecAttrKeyTypeRSA,
                               (id)kSecAttrKeySizeInBits: @2048,
                               (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate
                               };
    SecKeyRef privateKey = SecKeyCreateWithData((CFDataRef)keyData, (CFDictionaryRef)keyAttrs, NULL);
    if (privateKey == NULL)
        fail("create private key from data");

    // Create identity from certificate and private key.
    SecIdentityRef identity = SecIdentityCreate(kCFAllocatorDefault, cert, privateKey);
    CFRelease(privateKey);
    CFRelease(cert);

    return identity;
}

static void
CheckIdentityItem(NSString *accessGroup, OSStatus expectedStatus)
{
    OSStatus status;

    NSDictionary *check = @{
                             (id)kSecClass : (id)kSecClassIdentity,
                             (id)kSecAttrAccessGroup : accessGroup,
                             (id)kSecAttrLabel : @"item-delete-me",
                             (id)kSecUseDataProtectionKeychain: @YES,
                             };
    status = SecItemCopyMatching((__bridge CFDictionaryRef)check, NULL);
    if (status != expectedStatus)
        fail("check %s for %d item: %d", [accessGroup UTF8String], (int)expectedStatus, (int)status);
}

static void
CheckItemUpdateAccessGroupIdentity(void)
{
    OSStatus status;
    CFTypeRef ref = NULL;

    printf("[BEGIN] %s\n", __FUNCTION__);

    NSDictionary *clean1 = @{
        (id)kSecClass : (id)kSecClassIdentity,
        (id)kSecAttrAccessGroup : kAccessGroup1,
    };
    NSDictionary *clean2 = @{
        (id)kSecClass : (id)kSecClassIdentity,
        (id)kSecAttrAccessGroup : kAccessGroup2,
    };

    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);
    (void)SecItemDelete((__bridge CFDictionaryRef)clean2);

    CheckIdentityItem(kAccessGroup1, errSecItemNotFound);
    CheckIdentityItem(kAccessGroup2, errSecItemNotFound);

    SecIdentityRef identity = CreateTestIdentity();
    if (identity == NULL)
        fail("create private key from data");


    /*
     * Add item
     */

    NSDictionary *add = @{
        (id)kSecValueRef : (__bridge id)identity,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrLabel : @"item-delete-me",
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlock,
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecReturnPersistentRef: (id)kCFBooleanTrue,
    };
    status = SecItemAdd((__bridge CFDictionaryRef)add, &ref);
    if (status != errSecSuccess)
        fail("add item: %d: %s", (int)status, [[add description] UTF8String]);

    /*
     *
     */
    CheckIdentityItem(kAccessGroup1, errSecSuccess);
    CheckIdentityItem(kAccessGroup2, errSecItemNotFound);


    /*
     * Update access group
     */
    NSDictionary *query = @{
        (id)kSecClass : (id)kSecClassIdentity,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrLabel : @"item-delete-me",
        (id)kSecUseDataProtectionKeychain : (id)kCFBooleanTrue,
    };
    NSDictionary *modified = @{
        (id)kSecAttrAccessGroup : kAccessGroup2,
    };

    status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)modified);
    if (status != errSecSuccess)
        fail("cleanup2 item: %d", (int)status);

    /*
     *
     */

    CheckIdentityItem(kAccessGroup1, errSecItemNotFound);
    CheckIdentityItem(kAccessGroup2, errSecSuccess);

    /*
     * Check pref
     */
    CFDataRef data = NULL;

    NSDictionary *prefQuery = @{
        (id)kSecClass : (id)kSecClassIdentity,
        (id)kSecAttrAccessGroup : kAccessGroup2,
        (id)kSecAttrLabel : @"item-delete-me",
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecReturnPersistentRef : (id)kCFBooleanTrue,
    };
    status = SecItemCopyMatching((__bridge CFDictionaryRef)prefQuery, (CFTypeRef *)&data);
    if (status != errSecSuccess)
        fail("prefQuery item: %d", (int)status);

    /*
     * Update access group for identity
     */
    NSDictionary *query2 = @{
        (id)kSecValuePersistentRef : (__bridge id)data,
        (id)kSecUseDataProtectionKeychain : (id)kCFBooleanTrue,
    };
    NSDictionary *modified2 = @{
        (id)kSecAttrAccessGroup : kAccessGroup1,
    };

    status = SecItemUpdate((__bridge CFDictionaryRef)query2, (__bridge CFDictionaryRef)modified2);
    if (status != errSecInternal)
        fail("update identity with pref fails differntly: %d", (int)status);

/*
    CheckIdentityItem(kAccessGroup1, errSecSuccess);
    CheckIdentityItem(kAccessGroup2, errSecItemNotFound);
 */


    /*
     * Clean
     */
    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);
    (void)SecItemDelete((__bridge CFDictionaryRef)clean2);

    CFRelease(identity);

    CheckIdentityItem(kAccessGroup1, errSecItemNotFound);
    CheckIdentityItem(kAccessGroup2, errSecItemNotFound);


    printf("[PASS] %s\n", __FUNCTION__);
}

static void
CheckFindIdentityByReference(void)
{
    OSStatus status;
    CFDataRef pref = NULL, pref2 = NULL;

    printf("[BEGIN] %s\n", __FUNCTION__);

    /*
     * Clean identities
     */
    NSDictionary *clean1 = @{
        (id)kSecClass : (id)kSecClassIdentity,
        (id)kSecAttrAccessGroup : kAccessGroup1,
    };
    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);

    /*
     * Add
     */
    SecIdentityRef identity = CreateTestIdentity();
    if (identity == NULL)
        fail("create private key from data");


    NSDictionary *add = @{
        (id)kSecValueRef : (__bridge id)identity,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrLabel : @"CheckItemReference",
        (id)kSecAttrAccessible : (id)kSecAttrAccessibleAfterFirstUnlock,
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecReturnPersistentRef: (id)kCFBooleanTrue,
    };
    status = SecItemAdd((__bridge CFDictionaryRef)add, (CFTypeRef *)&pref);
    if (status != errSecSuccess)
        fail("add item: %d: %s", (int)status, [[add description] UTF8String]);

    if (pref == NULL || CFGetTypeID(pref) != CFDataGetTypeID())
        fail("no pref returned");

    /*
     * Find by identity
     */

    NSDictionary *query = @{
        (id)kSecValueRef : (__bridge id)identity,
        (id)kSecReturnPersistentRef: (id)kCFBooleanTrue,
    };
    status = SecItemCopyMatching((CFDictionaryRef)query, (CFTypeRef *)&pref2);
    if (status)
        fail("SecItemCopyMatching: %d", (int)status);

    if (pref2 == NULL || CFGetTypeID(pref2) != CFDataGetTypeID())
        fail("no pref2 returned");


    if (!CFEqual(pref, pref2))
        fail("prefs not same");

    CFRelease(pref2);

    /*
     * Find by label
     */

    NSDictionary *query2 = @{
        (id)kSecClass : (id)kSecClassIdentity,
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrLabel : @"CheckItemReference",
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecReturnPersistentRef: (id)kCFBooleanTrue,
    };
    status = SecItemCopyMatching((CFDictionaryRef)query2, (CFTypeRef *)&pref2);
    if (status)
        fail("SecItemCopyMatching: %d", (int)status);

    if (pref2 == NULL || CFGetTypeID(pref2) != CFDataGetTypeID())
        fail("no pref2 returned");
    
    
    if (!CFEqual(pref, pref2))
        fail("prefs not same");

    CFRelease(pref2);

    /*
     * Find by label + reference
     */

    NSDictionary *query3 = @{
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecAttrLabel : @"CheckItemReference",
        (id)kSecValueRef : (__bridge id)identity,
        (id)kSecUseDataProtectionKeychain: @YES,
        (id)kSecReturnPersistentRef: (id)kCFBooleanTrue,
    };
    status = SecItemCopyMatching((CFDictionaryRef)query3, (CFTypeRef *)&pref2);
    if (status)
        fail("SecItemCopyMatching: %d", (int)status);

    if (pref2 == NULL || CFGetTypeID(pref2) != CFDataGetTypeID())
        fail("no pref2 returned");
    
    
    if (!CFEqual(pref, pref2))
        fail("prefs not same");

    CFRelease(pref2);

    /*
     * Free stuff
     */

    CFRelease(pref);
    if(identity) {
        CFRelease(identity);
        identity = NULL;
    }

    printf("[PASS] %s\n", __FUNCTION__);
}

static uint64_t
timeDiff(uint64_t start, uint64_t stop)
{
    static uint64_t time_overhead_measured = 0;
    static double timebase_factor = 0;

    if (time_overhead_measured == 0) {
        uint64_t t0 = mach_absolute_time();
        time_overhead_measured = mach_absolute_time() - t0;

        struct mach_timebase_info timebase_info = {};
        mach_timebase_info(&timebase_info);
        timebase_factor = ((double)timebase_info.numer)/((double)timebase_info.denom);
    }

    return ((stop - start - time_overhead_measured) * timebase_factor) / NSEC_PER_USEC;
}

static void
RunCopyPerfTest(NSString *name, NSDictionary *query)
{
    uint64_t start = mach_absolute_time();
    OSStatus status;
    CFTypeRef result = NULL;

    status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    uint64_t stop = mach_absolute_time();

    if (status != 0) {
        printf("SecItemCopyMatching failed with: %d\n", (int)status);
        fflush(stdout);
        abort();
    }

    if (result)
        CFRelease(result);

    uint64_t us = timeDiff(start, stop);

    puts([[NSString stringWithFormat:@"[RESULT_KEY] SecItemCopyMatching-%@\n[RESULT_VALUE] %lu\n",
           name, (unsigned long)us] UTF8String]);
}

static void
RunDigestPerfTest(NSString *name, NSString *itemClass, NSString *accessGroup, NSUInteger expectedCount)
{
    uint64_t start = mach_absolute_time();
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    __block uint64_t stop;

    _SecItemFetchDigests(itemClass, accessGroup, ^(NSArray *items, NSError *error) {
        stop = mach_absolute_time();
        if (error) {
            printf("%s: _SecItemFetchDigests failed with: %ld\n", [name UTF8String], (long)error.code);
            fflush(stdout);
            abort();
        }
        dispatch_semaphore_signal(sema);

        if (expectedCount != [items count]) {
            printf("%s: _SecItemFetchDigests didn't return expected items: %ld\n", [name UTF8String], (long)[items count]);
            fflush(stdout);
            abort();
        }
    });
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);


    uint64_t us = timeDiff(start, stop);

    puts([[NSString stringWithFormat:@"[RESULT_KEY] SecItemCopyDigest-%@\n[RESULT_VALUE] %lu\n",
           name, (unsigned long)us] UTF8String]);
}


static void
CheckItemPerformance(void)
{
    unsigned n;

    printf("[BEGIN] %s\n", __FUNCTION__);

    /*
     * Clean identities
     */
    NSDictionary *clean1 = @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @"service",
        (id)kSecAttrAccessGroup : kAccessGroup1,
        (id)kSecUseDataProtectionKeychain : (id)kCFBooleanTrue,
    };
    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);

    NSData *data = [NSData dataWithBytes:"password" length:8];

    for (n = 0; n < 1000; n++) {
        NSDictionary *item = @{
            (id)kSecClass : (id)kSecClassGenericPassword,
            (id)kSecAttrAccount : [NSString stringWithFormat:@"account-%d", n],
            (id)kSecAttrService : @"service",
            (id)kSecUseDataProtectionKeychain : (id)kCFBooleanTrue,
            (id)kSecAttrAccessGroup : kAccessGroup1,
            (id)kSecUseDataProtectionKeychain: @YES,
            (id)kSecValueData : data,
        };
        SecItemAdd((__bridge CFDictionaryRef)item, NULL);
    }


    RunCopyPerfTest(@"FindOneItemLimit", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @"service",
        (id)kSecMatchLimit : (id)kSecMatchLimitOne,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunCopyPerfTest(@"FindOneItemUnique", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccount : @"account-0",
        (id)kSecAttrService : @"service",
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunCopyPerfTest(@"Find1000Items", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @"service",
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunDigestPerfTest(@"Digest1000Items", (id)kSecClassGenericPassword, kAccessGroup1, 1000);
    RunCopyPerfTest(@"GetAttrOneItemUnique", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccount : @"account-0",
        (id)kSecAttrService : @"service",
        (id)kSecReturnAttributes : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunCopyPerfTest(@"GetData1000Items", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @"service",
        (id)kSecReturnData : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunCopyPerfTest(@"GetDataOneItemUnique", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccount : @"account-0",
        (id)kSecAttrService : @"service",
        (id)kSecReturnData : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunCopyPerfTest(@"GetDataAttrOneItemUnique", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrAccount : @"account-0",
        (id)kSecAttrService : @"service",
        (id)kSecReturnData : (id)kCFBooleanTrue,
        (id)kSecReturnAttributes : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
#if TARGET_OS_IPHONE /* macOS doesn't support fetching data for more then one item */
    RunCopyPerfTest(@"GetData1000Items", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @"service",
        (id)kSecReturnData : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
    RunCopyPerfTest(@"GetDataAttr1000Items", @{
        (id)kSecClass : (id)kSecClassGenericPassword,
        (id)kSecAttrService : @"service",
        (id)kSecReturnData : (id)kCFBooleanTrue,
        (id)kSecReturnAttributes : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitAll,
        (id)kSecUseDataProtectionKeychain: @YES,
    });
#endif

    (void)SecItemDelete((__bridge CFDictionaryRef)clean1);


    printf("[PASS] %s\n", __FUNCTION__);
}

#if TARGET_OS_OSX
// This is specifically a test for legacy keychain, only on macos
static Boolean IsAttributeNumber(const NSDictionary* attributes, const NSString* whichAttr) {
    id theAttr = attributes[whichAttr];
    if (theAttr == nil) {
        fail("attributes dict does not contain key: %s", [whichAttr UTF8String]);
        return NO;
    }
    if (![theAttr isKindOfClass:[NSNumber class]]) {
        printf("%s attribute is not an NSNumber: %s\n", [whichAttr UTF8String], [[theAttr description] UTF8String]);
        return NO;
    }
    return YES;
}

static void
LegacyItemCopyMatchingCertificateTypeAndEncoding(void)
{
    OSStatus status;

    printf("[BEGIN] %s\n", __FUNCTION__);

    // Look up any cert
    NSDictionary* lookup = @{
        (id)kSecClass : (id)kSecClassCertificate,
        (id)kSecReturnAttributes : (id)kCFBooleanTrue,
        (id)kSecMatchLimit : (id)kSecMatchLimitOne,
    };
    CFTypeRef cfref = NULL;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)lookup, &cfref);
    if (status != errSecSuccess) {
        printf("[SKIP] %s\n", __FUNCTION__);
        return;
    }
    id checkResult = CFBridgingRelease(cfref);
    if (![checkResult isKindOfClass:[NSDictionary class]]) {
        fail("didn't get a dict");
    }
    NSDictionary* attributes = (NSDictionary*)checkResult;

    Boolean bothAreNumbers = IsAttributeNumber(attributes, (NSString *)kSecAttrCertificateType);
    // Don't short circuit on boolean logic, we want to know if both fail
    bothAreNumbers = IsAttributeNumber(attributes, (NSString *)kSecAttrCertificateEncoding) && bothAreNumbers;
    if (!bothAreNumbers) {
        fail("At least one of type & encoding is not an NSNumber");
    }

    printf("[PASS] %s\n", __FUNCTION__);
}
#endif //TARGET_OS_OSX

int
main(int argc, const char ** argv)
{
    printf("[TEST] secitemfunctionality\n");

    CheckItemPerformance();

    CheckFindIdentityByReference();

    //CheckItemAddDeleteMaybeLegacyKeychainNoData();
    CheckItemAddDeleteNoData();
    CheckItemUpdateAccessGroupGENP();
    CheckItemUpdateAccessGroupIdentity();
#if TARGET_OS_OSX
    LegacyItemCopyMatchingCertificateTypeAndEncoding();
#endif //TARGET_OS_OSX
    printf("[SUMMARY]\n");
    printf("test completed\n");

    return 0;
}
