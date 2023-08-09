// This file was automatically generated by protocompiler
// DO NOT EDIT!
// Compiled from OTAccountSettings.proto

#import "OTAccountSettings.h"
#import <ProtocolBuffer/PBConstants.h>
#import <ProtocolBuffer/PBHashUtil.h>
#import <ProtocolBuffer/PBDataReader.h>

#import "OTWalrus.h"
#import "OTWebAccess.h"

#if !__has_feature(objc_arc)
# error This generated file depends on ARC but it is not enabled; turn on ARC, or use 'objc_use_arc' option to generate non-ARC code.
#endif

@implementation OTAccountSettings

- (BOOL)hasWalrus
{
    return _walrus != nil;
}
@synthesize walrus = _walrus;
- (BOOL)hasWebAccess
{
    return _webAccess != nil;
}
@synthesize webAccess = _webAccess;

- (NSString *)description
{
    return [NSString stringWithFormat:@"%@ %@", [super description], [self dictionaryRepresentation]];
}

- (NSDictionary *)dictionaryRepresentation
{
    NSMutableDictionary *dict = [NSMutableDictionary dictionary];
    if (self->_walrus)
    {
        [dict setObject:[_walrus dictionaryRepresentation] forKey:@"walrus"];
    }
    if (self->_webAccess)
    {
        [dict setObject:[_webAccess dictionaryRepresentation] forKey:@"webAccess"];
    }
    return dict;
}

BOOL OTAccountSettingsReadFrom(__unsafe_unretained OTAccountSettings *self, __unsafe_unretained PBDataReader *reader) {
    while (PBReaderHasMoreData(reader)) {
        uint32_t tag = 0;
        uint8_t aType = 0;

        PBReaderReadTag32AndType(reader, &tag, &aType);

        if (PBReaderHasError(reader))
            break;

        if (aType == TYPE_END_GROUP) {
            break;
        }

        switch (tag) {

            case 1 /* walrus */:
            {
                OTWalrus *new_walrus = [[OTWalrus alloc] init];
                self->_walrus = new_walrus;
                PBDataReaderMark mark_walrus;
                BOOL markError = !PBReaderPlaceMark(reader, &mark_walrus);
                if (markError)
                {
                    return NO;
                }
                BOOL inError = !OTWalrusReadFrom(new_walrus, reader);
                if (inError)
                {
                    return NO;
                }
                PBReaderRecallMark(reader, &mark_walrus);
            }
            break;
            case 2 /* webAccess */:
            {
                OTWebAccess *new_webAccess = [[OTWebAccess alloc] init];
                self->_webAccess = new_webAccess;
                PBDataReaderMark mark_webAccess;
                BOOL markError = !PBReaderPlaceMark(reader, &mark_webAccess);
                if (markError)
                {
                    return NO;
                }
                BOOL inError = !OTWebAccessReadFrom(new_webAccess, reader);
                if (inError)
                {
                    return NO;
                }
                PBReaderRecallMark(reader, &mark_webAccess);
            }
            break;
            default:
                if (!PBReaderSkipValueWithTag(reader, tag, aType))
                    return NO;
                break;
        }
    }
    return !PBReaderHasError(reader);
}

- (BOOL)readFrom:(PBDataReader *)reader
{
    return OTAccountSettingsReadFrom(self, reader);
}
- (void)writeTo:(PBDataWriter *)writer
{
    /* walrus */
    {
        if (self->_walrus != nil)
        {
            PBDataWriterWriteSubmessage(writer, self->_walrus, 1);
        }
    }
    /* webAccess */
    {
        if (self->_webAccess != nil)
        {
            PBDataWriterWriteSubmessage(writer, self->_webAccess, 2);
        }
    }
}

- (void)copyTo:(OTAccountSettings *)other
{
    if (_walrus)
    {
        other.walrus = _walrus;
    }
    if (_webAccess)
    {
        other.webAccess = _webAccess;
    }
}

- (id)copyWithZone:(NSZone *)zone
{
    OTAccountSettings *copy = [[[self class] allocWithZone:zone] init];
    copy->_walrus = [_walrus copyWithZone:zone];
    copy->_webAccess = [_webAccess copyWithZone:zone];
    return copy;
}

- (BOOL)isEqual:(id)object
{
    OTAccountSettings *other = (OTAccountSettings *)object;
    return [other isMemberOfClass:[self class]]
    &&
    ((!self->_walrus && !other->_walrus) || [self->_walrus isEqual:other->_walrus])
    &&
    ((!self->_webAccess && !other->_webAccess) || [self->_webAccess isEqual:other->_webAccess])
    ;
}

- (NSUInteger)hash
{
    return 0
    ^
    [self->_walrus hash]
    ^
    [self->_webAccess hash]
    ;
}

- (void)mergeFrom:(OTAccountSettings *)other
{
    if (self->_walrus && other->_walrus)
    {
        [self->_walrus mergeFrom:other->_walrus];
    }
    else if (!self->_walrus && other->_walrus)
    {
        [self setWalrus:other->_walrus];
    }
    if (self->_webAccess && other->_webAccess)
    {
        [self->_webAccess mergeFrom:other->_webAccess];
    }
    else if (!self->_webAccess && other->_webAccess)
    {
        [self setWebAccess:other->_webAccess];
    }
}

@end
