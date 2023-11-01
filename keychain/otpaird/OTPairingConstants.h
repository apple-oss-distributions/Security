#define OTPairingMachServiceName    "com.apple.security.otpaird"

#define OTPairingIDSServiceName     @"com.apple.private.alloy.octagon"

#define OTPairingIDSKeyMessageType  @"m"
#define OTPairingIDSKeySession      @"session"
#define OTPairingIDSKeyPacket       @"packet"
#define OTPairingIDSKeyErrorDescription @"error"

enum OTPairingIDSMessageType {
    OTPairingIDSMessageTypePacket = 1,
    OTPairingIDSMessageTypeError =  2,
    OTPairingIDSMessageTypePoke =   3,
};

#define OTPairingXPCKeyOperation    "operation"
#define OTPairingXPCKeyError        "error"
#define OTPairingXPCKeySuccess      "success"

#define OTPairingErrorDomain        @"com.apple.security.otpaird"
enum OTPairingErrorType {
    OTPairingSuccess = 0,
    OTPairingErrorTypeLock = 1,
    OTPairingErrorTypeXPC = 2,
    OTPairingErrorTypeIDS = 3,
    OTPairingErrorTypeRemote = 4,
    OTPairingErrorTypeAlreadyIn = 5,
    OTPairingErrorTypeBusy = 6,
    OTPairingErrorTypeKCPairing = 7,
    OTPairingErrorTypeSessionTimeout = 8,
};

enum {
    OTPairingOperationInitiate = 1,
};

#define OTPairingXPCActivityIdentifier  "com.apple.security.otpaird.pairing"
#define OTPairingXPCActivityInterval    XPC_ACTIVITY_INTERVAL_15_MIN

#define OTPairingXPCActivityPoke        "com.apple.security.otpaird.poke"

#define OTPairingXPCEventIDSDeviceState "ids-device-state"
