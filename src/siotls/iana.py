import enum
import math

class HexEnum(enum.IntEnum):
    def __repr__(self):
        digits = math.ceil(self.value.bit_length() / 8) * 2
        return f'<{type(self).__name__}.{self.name}: {self.value} (0x{self.value:0{digits}x})>'


class AlertLevel(HexEnum):
    WARNING = 1
    FATAL = 2


class AlertDescription(HexEnum):
    CLOSE_NOTIFY = 0
    UNEXPECTED_MESSAGE = 10
    BAD_RECORD_MAC = 20
    RECORD_OVERFLOW = 22
    HANDSHAKE_FAILURE = 40
    BAD_CERTIFICATE = 42
    UNSUPPORTED_CERTIFICATE = 43
    CERTIFICATE_REVOKED = 44
    CERTIFICATE_EXPIRED = 45
    CERTIFICATE_UNKNOWN = 46
    ILLEGAL_PARAMETER = 47
    UNKNOWN_CA = 48
    ACCESS_DENIED = 49
    DECODE_ERROR = 50
    DECRYPT_ERROR = 51
    PROTOCOL_VERSION = 70
    INSUFFICIENT_SECURITY = 71
    INTERNAL_ERROR = 80
    INAPPROPRIATE_FALLBACK = 86
    USER_CANCELED = 90
    MISSING_EXTENSION = 109
    UNSUPPORTED_EXTENSION = 110
    UNRECOGNIZED_NAME = 112
    BAD_CERTIFICATE_STATUS_RESPONSE = 113
    UNKNOWN_PSK_IDENTITY = 115
    CERTIFICATE_REQUIRED = 116
    NO_APPLICATION_PROTOCOL = 120


class CipherSuites(enum.Enum):
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = (0x00, 0xff)
    TLS_AES_128_GCM_SHA256 = (0x13, 0x01)
    TLS_AES_256_GCM_SHA384 = (0x13, 0x02)
    TLS_CHACHA20_POLY1305_SHA256 = (0x13, 0x03)
    TLS_AES_128_CCM_SHA256 = (0x13, 0x04)
    TLS_AES_128_CCM_8_SHA256 = (0x13, 0x05)

    def __repr__(self):
        return (f'<{type(self).__name__}.{self.name}: '
                f'{self.value} (0x{self.value[0]:02x}{self.value[1]:02x})>')



class ContentType(HexEnum):
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23


class ExtensionType(HexEnum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13
    USE_SRTP = 14
    HEARTBEAT = 15
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION = 16
    SIGNED_CERTIFICATE_TIMESTAMP = 18
    CLIENT_CERTIFICATE_TYPE = 19
    SERVER_CERTIFICATE_TYPE = 20
    PADDING = 21
    PRE_SHARED_KEY = 41
    EARLY_DATA = 42
    SUPPORTED_VERSIONS = 43
    COOKIE = 44
    PSK_KEY_EXCHANGE_MODES = 45
    CERTIFICATE_AUTHORITIES = 47
    OID_FILTERS = 48
    POST_HANDSHAKE_AUTH = 49
    SIGNATURE_ALGORITHMS_CERT = 50
    KEY_SHARE = 51


class HandshakeType(HexEnum):
    CLIENT_HELLO = 1
    SERVER_HELLO = 2
    NEW_SESSION_TICKET = 4
    END_OF_EARLY_DATA = 5
    ENCRYPTED_EXTENSIONS = 8
    CERTIFICATE = 11
    CERTIFICATE_REQUEST = 13
    CERTIFICATE_VERIFY = 15
    FINISHED = 20
    KEY_UPDATE = 24
    MESSAGE_HASH = 254



# Not IANA
class TLSVersion(HexEnum):
    TLS_1_0 = 0x0301
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304

#
#  Extensions
#

class NameType(HexEnum):
    HOST_NAME = 0

class MaxFragmentLength(HexEnum):
    LIMIT_512 = 1
    LIMIT_1024 = 2
    LIMIT_2048 = 3
    LIMIT_4096 = 4
