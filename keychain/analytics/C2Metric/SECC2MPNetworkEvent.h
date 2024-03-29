// This file was automatically generated by protocompiler
// DO NOT EDIT!
// Compiled from C2Metric.proto

#import <Foundation/Foundation.h>
#import <ProtocolBuffer/PBCodable.h>

@class SECC2MPError;

typedef NS_ENUM(int32_t, SECC2MPNetworkEvent_Trigger) {
    SECC2MPNetworkEvent_Trigger_none_trigger = 0,
    SECC2MPNetworkEvent_Trigger_user_default_trigger = 1,
    SECC2MPNetworkEvent_Trigger_frequency_trigger = 2,
    SECC2MPNetworkEvent_Trigger_response_header_trigger = 4,
};
#ifdef __OBJC__
NS_INLINE NSString *SECC2MPNetworkEvent_TriggerAsString(SECC2MPNetworkEvent_Trigger value)
{
    switch (value)
    {
        case SECC2MPNetworkEvent_Trigger_none_trigger: return @"none_trigger";
        case SECC2MPNetworkEvent_Trigger_user_default_trigger: return @"user_default_trigger";
        case SECC2MPNetworkEvent_Trigger_frequency_trigger: return @"frequency_trigger";
        case SECC2MPNetworkEvent_Trigger_response_header_trigger: return @"response_header_trigger";
        default: return [NSString stringWithFormat:@"(unknown: %i)", value];
    }
}
#endif /* __OBJC__ */
#ifdef __OBJC__
NS_INLINE SECC2MPNetworkEvent_Trigger StringAsSECC2MPNetworkEvent_Trigger(NSString *value)
{
    if ([value isEqualToString:@"none_trigger"]) return SECC2MPNetworkEvent_Trigger_none_trigger;
    if ([value isEqualToString:@"user_default_trigger"]) return SECC2MPNetworkEvent_Trigger_user_default_trigger;
    if ([value isEqualToString:@"frequency_trigger"]) return SECC2MPNetworkEvent_Trigger_frequency_trigger;
    if ([value isEqualToString:@"response_header_trigger"]) return SECC2MPNetworkEvent_Trigger_response_header_trigger;
    return SECC2MPNetworkEvent_Trigger_none_trigger;
}
#endif /* __OBJC__ */

#ifdef __cplusplus
#define SECC2MPNETWORKEVENT_FUNCTION extern "C" __attribute__((visibility("hidden")))
#else
#define SECC2MPNETWORKEVENT_FUNCTION extern __attribute__((visibility("hidden")))
#endif

__attribute__((visibility("hidden")))
@interface SECC2MPNetworkEvent : PBCodable <NSCopying>
{
    uint64_t _networkRequestBodyBytesSent;
    uint64_t _networkResponseBodyBytesReceived;
    uint64_t _networkStatusCode;
    uint64_t _reportFrequency;
    uint64_t _reportFrequencyBase;
    uint64_t _timestampC2Init;
    uint64_t _timestampC2Now;
    uint64_t _timestampC2Start;
    uint64_t _timestampDnsEnd;
    uint64_t _timestampDnsStart;
    uint64_t _timestampRequestEnd;
    uint64_t _timestampRequestStart;
    uint64_t _timestampResponseEnd;
    uint64_t _timestampResponseStart;
    uint64_t _timestampSslStart;
    uint64_t _timestampTcpEnd;
    uint64_t _timestampTcpStart;
    uint64_t _triggers;
    NSString *_networkConnectionUuid;
    SECC2MPError *_networkFatalError;
    NSString *_networkHostname;
    NSString *_networkInterfaceIdentifier;
    uint32_t _networkPreviousAttemptCount;
    NSString *_networkProtocolName;
    NSString *_networkRemoteAddresssAndPort;
    uint32_t _networkRequestHeaderSize;
    NSString *_networkRequestUri;
    uint32_t _networkResponseHeaderSize;
    NSString *_networkTaskDescription;
    NSString *_optionsQualityOfService;
    NSString *_optionsSourceApplicationBundleIdentifier;
    NSString *_optionsSourceApplicationSecondaryIdentifier;
    uint32_t _optionsTimeoutIntervalForRequest;
    uint32_t _optionsTimeoutIntervalForResource;
    BOOL _networkConnectionReused;
    BOOL _optionsAllowExpensiveAccess;
    BOOL _optionsAllowPowerNapScheduling;
    BOOL _optionsAppleIdContext;
    BOOL _optionsOutOfProcess;
    BOOL _optionsOutOfProcessForceDiscretionary;
    BOOL _optionsTlsPinningRequired;
    struct {
        uint networkRequestBodyBytesSent:1;
        uint networkResponseBodyBytesReceived:1;
        uint networkStatusCode:1;
        uint reportFrequency:1;
        uint reportFrequencyBase:1;
        uint timestampC2Init:1;
        uint timestampC2Now:1;
        uint timestampC2Start:1;
        uint timestampDnsEnd:1;
        uint timestampDnsStart:1;
        uint timestampRequestEnd:1;
        uint timestampRequestStart:1;
        uint timestampResponseEnd:1;
        uint timestampResponseStart:1;
        uint timestampSslStart:1;
        uint timestampTcpEnd:1;
        uint timestampTcpStart:1;
        uint triggers:1;
        uint networkPreviousAttemptCount:1;
        uint networkRequestHeaderSize:1;
        uint networkResponseHeaderSize:1;
        uint optionsTimeoutIntervalForRequest:1;
        uint optionsTimeoutIntervalForResource:1;
        uint networkConnectionReused:1;
        uint optionsAllowExpensiveAccess:1;
        uint optionsAllowPowerNapScheduling:1;
        uint optionsAppleIdContext:1;
        uint optionsOutOfProcess:1;
        uint optionsOutOfProcessForceDiscretionary:1;
        uint optionsTlsPinningRequired:1;
    } _has;
}


@property (nonatomic) BOOL hasTriggers;
/** Deprecated. Use Metric.triggers instead. */
@property (nonatomic) uint64_t triggers;

@property (nonatomic) BOOL hasReportFrequency;
/** Deprecated. Use Metric.report_frequency instead. */
@property (nonatomic) uint64_t reportFrequency;

@property (nonatomic) BOOL hasReportFrequencyBase;
/** Deprecated. Use Metric.report_frequency_base instead. */
@property (nonatomic) uint64_t reportFrequencyBase;

@property (nonatomic, readonly) BOOL hasNetworkTaskDescription;
@property (nonatomic, retain) NSString *networkTaskDescription;

@property (nonatomic, readonly) BOOL hasNetworkHostname;
@property (nonatomic, retain) NSString *networkHostname;

@property (nonatomic, readonly) BOOL hasNetworkRemoteAddresssAndPort;
@property (nonatomic, retain) NSString *networkRemoteAddresssAndPort;

@property (nonatomic, readonly) BOOL hasNetworkConnectionUuid;
@property (nonatomic, retain) NSString *networkConnectionUuid;

@property (nonatomic) BOOL hasNetworkConnectionReused;
@property (nonatomic) BOOL networkConnectionReused;

@property (nonatomic, readonly) BOOL hasNetworkInterfaceIdentifier;
@property (nonatomic, retain) NSString *networkInterfaceIdentifier;

@property (nonatomic, readonly) BOOL hasNetworkProtocolName;
@property (nonatomic, retain) NSString *networkProtocolName;

@property (nonatomic) BOOL hasNetworkRequestHeaderSize;
@property (nonatomic) uint32_t networkRequestHeaderSize;

@property (nonatomic) BOOL hasNetworkRequestBodyBytesSent;
@property (nonatomic) uint64_t networkRequestBodyBytesSent;

@property (nonatomic) BOOL hasNetworkResponseHeaderSize;
@property (nonatomic) uint32_t networkResponseHeaderSize;

@property (nonatomic) BOOL hasNetworkResponseBodyBytesReceived;
@property (nonatomic) uint64_t networkResponseBodyBytesReceived;

@property (nonatomic) BOOL hasNetworkPreviousAttemptCount;
@property (nonatomic) uint32_t networkPreviousAttemptCount;

@property (nonatomic, readonly) BOOL hasNetworkFatalError;
@property (nonatomic, retain) SECC2MPError *networkFatalError;

@property (nonatomic) BOOL hasNetworkStatusCode;
@property (nonatomic) uint64_t networkStatusCode;

@property (nonatomic, readonly) BOOL hasNetworkRequestUri;
@property (nonatomic, retain) NSString *networkRequestUri;

@property (nonatomic) BOOL hasTimestampC2Init;
@property (nonatomic) uint64_t timestampC2Init;

@property (nonatomic) BOOL hasTimestampC2Start;
@property (nonatomic) uint64_t timestampC2Start;

@property (nonatomic) BOOL hasTimestampC2Now;
@property (nonatomic) uint64_t timestampC2Now;

@property (nonatomic) BOOL hasTimestampDnsStart;
@property (nonatomic) uint64_t timestampDnsStart;

@property (nonatomic) BOOL hasTimestampDnsEnd;
@property (nonatomic) uint64_t timestampDnsEnd;

@property (nonatomic) BOOL hasTimestampTcpStart;
@property (nonatomic) uint64_t timestampTcpStart;

@property (nonatomic) BOOL hasTimestampTcpEnd;
@property (nonatomic) uint64_t timestampTcpEnd;

@property (nonatomic) BOOL hasTimestampSslStart;
@property (nonatomic) uint64_t timestampSslStart;

@property (nonatomic) BOOL hasTimestampRequestStart;
@property (nonatomic) uint64_t timestampRequestStart;

@property (nonatomic) BOOL hasTimestampRequestEnd;
@property (nonatomic) uint64_t timestampRequestEnd;

@property (nonatomic) BOOL hasTimestampResponseStart;
@property (nonatomic) uint64_t timestampResponseStart;

@property (nonatomic) BOOL hasTimestampResponseEnd;
@property (nonatomic) uint64_t timestampResponseEnd;

@property (nonatomic, readonly) BOOL hasOptionsQualityOfService;
@property (nonatomic, retain) NSString *optionsQualityOfService;

@property (nonatomic) BOOL hasOptionsOutOfProcess;
@property (nonatomic) BOOL optionsOutOfProcess;

@property (nonatomic) BOOL hasOptionsOutOfProcessForceDiscretionary;
@property (nonatomic) BOOL optionsOutOfProcessForceDiscretionary;

@property (nonatomic) BOOL hasOptionsAllowExpensiveAccess;
@property (nonatomic) BOOL optionsAllowExpensiveAccess;

@property (nonatomic) BOOL hasOptionsAllowPowerNapScheduling;
@property (nonatomic) BOOL optionsAllowPowerNapScheduling;

@property (nonatomic) BOOL hasOptionsTimeoutIntervalForRequest;
@property (nonatomic) uint32_t optionsTimeoutIntervalForRequest;

@property (nonatomic) BOOL hasOptionsTimeoutIntervalForResource;
@property (nonatomic) uint32_t optionsTimeoutIntervalForResource;

@property (nonatomic, readonly) BOOL hasOptionsSourceApplicationBundleIdentifier;
@property (nonatomic, retain) NSString *optionsSourceApplicationBundleIdentifier;

@property (nonatomic, readonly) BOOL hasOptionsSourceApplicationSecondaryIdentifier;
@property (nonatomic, retain) NSString *optionsSourceApplicationSecondaryIdentifier;

@property (nonatomic) BOOL hasOptionsAppleIdContext;
@property (nonatomic) BOOL optionsAppleIdContext;

@property (nonatomic) BOOL hasOptionsTlsPinningRequired;
@property (nonatomic) BOOL optionsTlsPinningRequired;

// Performs a shallow copy into other
- (void)copyTo:(SECC2MPNetworkEvent *)other;

// Performs a deep merge from other into self
// If set in other, singular values in self are replaced in self
// Singular composite values are recursively merged
// Repeated values from other are appended to repeated values in self
- (void)mergeFrom:(SECC2MPNetworkEvent *)other;

SECC2MPNETWORKEVENT_FUNCTION BOOL SECC2MPNetworkEventReadFrom(__unsafe_unretained SECC2MPNetworkEvent *self, __unsafe_unretained PBDataReader *reader);

@end

