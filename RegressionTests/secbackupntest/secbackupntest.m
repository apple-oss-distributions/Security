//
//  Copyright 2015 Apple. All rights reserved.
//

#include <Foundation/Foundation.h>
#include <Security/Security.h>

#include <TargetConditionals.h>

#include <Security/SecItemPriv.h>
#include <err.h>

#if !TARGET_OS_SIMULATOR
#include <AppleKeyStore/libaks.h>

static NSData *
BagMe(void)
{
    keybag_handle_t handle;
    kern_return_t result;
    void *data = NULL;
    int length;

    result = aks_create_bag("foo", 3, kAppleKeyStoreAsymmetricBackupBag, &handle);
    if (result)
        errx(1, "aks_create_bag: %08x", result);

    result = aks_save_bag(handle, &data, &length);
    if (result)
        errx(1, "aks_save_bag");

    return [NSData dataWithBytes:data length:length];
}
#endif /* TARGET_OS_SIMULATOR */

int main (int argc, const char * argv[])
{
    @autoreleasepool {
        NSData *bag = NULL, *password = NULL;

#if !TARGET_OS_SIMULATOR
        bag = BagMe();
        password = [NSData dataWithBytes:"foo" length:3];
#endif

        NSLog(@"backup bag: %@", bag);

        NSData *backup = (__bridge NSData *)_SecKeychainCopyBackup((__bridge CFDataRef)bag, (__bridge CFDataRef)password);
        if (backup != NULL) {
            NSLog(@"backup data: %@", backup);
            errx(1, "got backup");
        }
        return 0;
    }
}


