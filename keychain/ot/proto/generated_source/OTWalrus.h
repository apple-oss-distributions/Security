// This file was automatically generated by protocompiler
// DO NOT EDIT!
// Compiled from OTAccountSettings.proto

#import <Foundation/Foundation.h>
#import <ProtocolBuffer/PBCodable.h>

#ifdef __cplusplus
#define OTWALRUS_FUNCTION extern "C"
#else
#define OTWALRUS_FUNCTION extern
#endif

@interface OTWalrus : PBCodable <NSCopying>
{
    BOOL _enabled;
    struct {
        int enabled:1;
    } _has;
}


@property (nonatomic) BOOL hasEnabled;
@property (nonatomic) BOOL enabled;

// Performs a shallow copy into other
- (void)copyTo:(OTWalrus *)other;

// Performs a deep merge from other into self
// If set in other, singular values in self are replaced in self
// Singular composite values are recursively merged
// Repeated values from other are appended to repeated values in self
- (void)mergeFrom:(OTWalrus *)other;

OTWALRUS_FUNCTION BOOL OTWalrusReadFrom(__unsafe_unretained OTWalrus *self, __unsafe_unretained PBDataReader *reader);

@end
