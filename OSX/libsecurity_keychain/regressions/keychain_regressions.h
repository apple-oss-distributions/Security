/* To add a test:
 1) add it here
 2) Add it as command line argument for SecurityTest.app in the Release and Debug schemes
 */
#include <regressions/test/testmore.h>

ONE_TEST(kc_01_keychain_creation)
ONE_TEST(kc_02_unlock_noui)
ONE_TEST(kc_03_status)
ONE_TEST(kc_03_keychain_list)
ONE_TEST(kc_04_is_valid)
ONE_TEST(kc_05_find_existing_items)
ONE_TEST(kc_05_find_existing_items_locked)
ONE_TEST(kc_06_cert_search_email)
ONE_TEST(kc_10_item_add_generic)
ONE_TEST(kc_10_item_add_internet)
ONE_TEST(kc_10_item_add_certificate)
ONE_TEST(kc_12_key_create_symmetric)
ONE_TEST(kc_12_key_create_symmetric_and_use)
ONE_TEST(kc_15_key_update_valueref)
ONE_TEST(kc_15_item_update_label_skimaad)
ONE_TEST(kc_16_item_update_password)
ONE_TEST(kc_17_item_find_key)
ONE_TEST(kc_18_find_combined)
ONE_TEST(kc_19_item_copy_internet)
ONE_TEST(kc_20_identity_persistent_refs)
ONE_TEST(kc_20_identity_key_attributes)
ONE_TEST(kc_20_identity_find_stress)
ONE_TEST(kc_20_key_find_stress)
ONE_TEST(kc_20_item_add_stress)
ONE_TEST(kc_20_item_find_stress)
ONE_TEST(kc_20_item_delete_stress)
ONE_TEST(kc_21_item_use_callback)
ONE_TEST(kc_21_item_xattrs)
ONE_TEST(kc_23_key_export_symmetric)
ONE_TEST(kc_24_key_copy_keychain)
ONE_TEST(kc_26_key_import_public)
ONE_TEST(kc_27_key_non_extractable)
ONE_TEST(kc_28_p12_import)
ONE_TEST(kc_28_cert_sign)
ONE_TEST(kc_30_xara)
ONE_TEST(kc_40_seckey)
ONE_TEST(kc_41_sececkey)
ONE_TEST(kc_42_trust_revocation)
ONE_TEST(kc_43_seckey_interop)
ONE_TEST(kc_44_secrecoverypassword)
ONE_TEST(kc_45_change_password)
ONE_TEST(si_20_sectrust_provisioning)
ONE_TEST(si_33_keychain_backup)
ONE_TEST(si_34_one_true_keychain)