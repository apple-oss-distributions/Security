//
//  LWCRHelper.mm
//  Security
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <TLE/TLE.h>
#import <kern/cs_blobs.h>
#import <security_utilities/debugging.h>
#import "LWCRHelper.h"
#import <TargetConditionals.h>

#if TARGET_OS_SIMULATOR
// lwcr_keys.h doesn't exist for simulator builds yet...
#ifndef kLWCRFact_ValidationCategory
#define kLWCRFact_ValidationCategory "validation-category"
#endif
#ifndef kLWCRFact_SigningIdentifier
#define kLWCRFact_SigningIdentifier "signing-identifier"
#endif
#ifndef kLWCRFact_TeamIdentifier
#define kLWCRFact_TeamIdentifier "team-identifier"
#endif
#ifndef kLWCROperator_Or
#define kLWCROperator_Or "$or"
#endif
#ifndef kLWCROperator_And
#define kLWCROperator_And "$and"
#endif
#ifndef kLWCRFact_CDhash
#define kLWCRFact_CDhash "cdhash"
#endif
#ifndef kLWCROperator_In
#define kLWCROperator_In "$in"
#endif
#else
#import <lwcr_keys.h>
#endif


// anchor apple
const uint8_t platformReqData[] = {
	0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03
};
const size_t platformReqDataLen = sizeof(platformReqData);

// anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.25.1] or certificate leaf[1.2.840.113635.100.6.1.25.2]
// 1.2.840.113635.100.6.1.25.1 - Testflight Prod
// 1.2.840.113635.100.6.1.25.2 - Testflight QA
const uint8_t testflightReqData[] = {
	0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
	0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x19, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const size_t testflightReqDataLen = sizeof(testflightReqData);

// anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.1] and (certificate leaf[field.1.2.840.113635.100.6.1.2] or certificate leaf[field.1.2.840.113635.100.6.1.12])
// 1.2.840.113635.100.6.2.1 - WWDR CA
// 1.2.840.113635.100.6.1.2 - Apple Developer
// 1.2.840.113635.100.6.1.12 - Mac Developer
const uint8_t developmentReqData[] = {
	0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
	0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x01, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x02, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const size_t developmentReqDataLen = sizeof(developmentReqData);

// anchor apple generic and (certificate leaf[field.1.2.840.113635.100.6.1.9] or certificate leaf[field.1.2.840.113635.100.6.1.9.1] or certificate leaf[field.1.2.840.113635.100.6.1.3] or certificate leaf[field.1.2.840.113635.100.6.1.3.1] or certificate leaf[field.1.2.840.113635.100.6.1.24] or certificate leaf[field.1.2.840.113635.100.6.1.24.1])
// 1.2.840.113635.100.6.1.9 - Mac App Store Prod
// 1.2.840.113635.100.6.1.9.1 - Mac App Store QA
// 1.2.840.113635.100.6.1.3 - iOS App Store Prod
// 1.2.840.113635.100.6.1.3.1 - iOS App Store QA
// 1.2.840.113635.100.6.1.24 - tvOS App Store Prod
// 1.2.840.113635.100.6.1.24.1 - tvOS App Store QA
const uint8_t appStoreReqData[] = {
	0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
	0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07,
	0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x09, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x09, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x63, 0x64, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06,
	0x01, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x18, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const size_t appStoreReqDataLen = sizeof(appStoreReqData);

// anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13]
// 1.2.840.113635.100.6.2.6 - Developer ID CA
// 1.2.840.113635.100.6.1.13 - Developer ID
const uint8_t developerIDReqData[] = {
	0xfa, 0xde, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
	0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x01,
	0x00, 0x00, 0x00, 0x0a, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x02, 0x06, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x06, 0x01, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
const size_t developerIDReqDataLen = sizeof(developerIDReqData);

static NSDictionary* defaultPlatformLWCR(const char* signingIdentifier)
{
	if (signingIdentifier == NULL) {
		secerror("%s: signing identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	NSDictionary* lwcr = @{
		@kLWCRFact_ValidationCategory:@(CS_VALIDATION_CATEGORY_PLATFORM),
		@kLWCRFact_SigningIdentifier:@(signingIdentifier)
	};
	return lwcr;
}

static NSDictionary* defaultTestflightLWCR(const char* signingIdentifier)
{
	if (signingIdentifier == NULL) {
		secerror("%s: signing identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	NSDictionary* lwcr = @{
		@kLWCRFact_ValidationCategory:@(CS_VALIDATION_CATEGORY_TESTFLIGHT),
		@kLWCRFact_SigningIdentifier:@(signingIdentifier)
	};
	return lwcr;
}

static NSDictionary* defaultDevelopmentLWCR(const char* signingIdentifier, const char* teamIdentifier)
{
	if (signingIdentifier == NULL) {
		secerror("%s: signing identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	if (teamIdentifier == NULL) {
		secerror("%s: team identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	NSDictionary* lwcr = @{
		@kLWCRFact_ValidationCategory:@(CS_VALIDATION_CATEGORY_DEVELOPMENT),
		@kLWCRFact_SigningIdentifier:@(signingIdentifier),
		@kLWCRFact_TeamIdentifier:@(teamIdentifier),
	};
	return lwcr;
}

static NSDictionary* defaultAppStoreLWCR(const char* signingIdentifier, const char* teamIdentifier)
{
	if (signingIdentifier == NULL) {
		secerror("%s: signing identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	if (teamIdentifier == NULL) {
		secerror("%s: team identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	NSDictionary* lwcr = @{
		@kLWCROperator_Or: @{
			@kLWCRFact_ValidationCategory:@(CS_VALIDATION_CATEGORY_APP_STORE),
			@kLWCROperator_And:@{
				@kLWCRFact_ValidationCategory:@(CS_VALIDATION_CATEGORY_DEVELOPER_ID),
				@kLWCRFact_TeamIdentifier:@(teamIdentifier)
			}
		},
		@kLWCRFact_SigningIdentifier:@(signingIdentifier),
	};
	return lwcr;
}

static NSDictionary* defaultDeveloperIDLWCR(const char* signingIdentifier, const char* teamIdentifier)
{
	if (signingIdentifier == NULL) {
		secerror("%s: signing identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	if (teamIdentifier == NULL) {
		secerror("%s: team identifier is NULL, cannot generate a LWCR",__FUNCTION__);
		return nil;
	}
	NSDictionary* lwcr = @{
		@kLWCRFact_ValidationCategory:@(CS_VALIDATION_CATEGORY_DEVELOPER_ID),
		@kLWCRFact_SigningIdentifier:@(signingIdentifier),
		@kLWCRFact_TeamIdentifier:@(teamIdentifier),
	};
	return lwcr;
}

static NSDictionary* defaultAdhocLWCR(NSArray* allCdhashes)
{
	if (allCdhashes == nil || allCdhashes.count == 0) {
		secerror("%s: no cdhashes for code, cannot generate a LWCR", __FUNCTION__);
		return nil;
	}
	NSDictionary* lwcr = @{
		@kLWCRFact_CDhash : @{
			@kLWCROperator_In: allCdhashes
		},
	};
	return lwcr;
}

CFDictionaryRef copyDefaultDesignatedLWCRMaker(unsigned int validationCategory,
											   const char* signingIdentifier,
											   const char* teamIdentifier,
											   CFArrayRef allCdhashes)
{
	NSDictionary* lwcr = nil;
	switch (validationCategory) {
	case CS_VALIDATION_CATEGORY_PLATFORM:
		lwcr = defaultPlatformLWCR(signingIdentifier);
		break;
	case CS_VALIDATION_CATEGORY_TESTFLIGHT:
		lwcr = defaultTestflightLWCR(signingIdentifier);
		break;
	case CS_VALIDATION_CATEGORY_DEVELOPMENT:
		lwcr = defaultDevelopmentLWCR(signingIdentifier, teamIdentifier);
		break;
	case CS_VALIDATION_CATEGORY_APP_STORE:
		lwcr = defaultAppStoreLWCR(signingIdentifier, teamIdentifier);
		break;
	case CS_VALIDATION_CATEGORY_DEVELOPER_ID:
		lwcr = defaultDeveloperIDLWCR(signingIdentifier, teamIdentifier);
		break;
	default:
		lwcr = defaultAdhocLWCR((__bridge NSArray*)allCdhashes);
		break;
	}
	return (__bridge_retained CFDictionaryRef)lwcr;
}
