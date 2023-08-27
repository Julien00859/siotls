import enum


class Hex1Enum(enum.IntEnum):
    """ An integer on 1 byte with hexadecimal representation """
    def __repr__(self):
        return f'<{type(self).__name__}.{self.name}: {self.value} (0x{self.value:02x})>'


class Hex2Enum(enum.IntEnum):
    """ An integer on 2 bytes with hexadecimal representation """
    def __repr__(self):
        return f'<{type(self).__name__}.{self.name}: {self.value} (0x{self.value:04x})>'


class AlertLevel(Hex1Enum):
    WARNING = 1
    FATAL = 2


class AlertDescription(Hex1Enum):
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


class CipherSuites(Hex2Enum):
    # The actual type in uint8_t[2] and not uint16_t but we want to use
    # an IntEnum in Python to ease serialization
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff
    TLS_AES_128_GCM_SHA256 = 0x1301
    TLS_AES_256_GCM_SHA384 = 0x1302
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303
    TLS_AES_128_CCM_SHA256 = 0x1304
    TLS_AES_128_CCM_8_SHA256 = 0x1305


class ContentType(Hex1Enum):
    INVALID = 0
    CHANGE_CIPHER_SPEC = 20
    ALERT = 21
    HANDSHAKE = 22
    APPLICATION_DATA = 23

    HEARTBEAT = 24


class HandshakeType(Hex1Enum):
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


class HeartbeatMessageType(Hex1Enum):
    heartbeat_request = 1
    heartbeat_response = 2


#-----------------------------------------------------------------------
# Extension related types
#-----------------------------------------------------------------------

class ExtensionType(Hex2Enum):
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


class NameType(Hex1Enum):
    HOST_NAME = 0


class MaxFragmentLength(Hex1Enum):
    LIMIT_512 = 1
    LIMIT_1024 = 2
    LIMIT_2048 = 3
    LIMIT_4096 = 4


class CertificateStatusType(Hex1Enum):
    OCSP = 1


class NamedGroup(Hex2Enum):
    # ELLIPTIC Curve Groups (ECDHE)
    SECP256R1 = 0x0017
    SECP384R1 = 0x0018
    SECP521R1 = 0x0019
    X25519 = 0x001D
    X448 = 0x001E

    # Finite Field Groups (DHE)
    FFDHE2048 = 0x0100
    FFDHE3072 = 0x0101
    FFDHE4096 = 0x0102
    FFDHE6144 = 0x0103
    FFDHE8192 = 0x0104


class SignatureScheme(Hex2Enum):
    # RSASSA-PKCS1-v1_5 algorithms
    RSA_PKCS1_SHA256 = 0x0401
    RSA_PKCS1_SHA384 = 0x0501
    RSA_PKCS1_SHA512 = 0x0601

    # ECDSA algorithms
    ECDSA_SECP256R1_SHA256 = 0x0403
    ECDSA_SECP384R1_SHA384 = 0x0503
    ECDSA_SECP521R1_SHA512 = 0x0603

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    RSA_PSS_RSAE_SHA256 = 0x0804
    RSA_PSS_RSAE_SHA384 = 0x0805
    RSA_PSS_RSAE_SHA512 = 0x0806

    # EdDSA algorithms
    ED25519 = 0x0807
    ED448 = 0x0808

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    RSA_PSS_PSS_SHA256 = 0x0809
    RSA_PSS_PSS_SHA384 = 0x080a
    RSA_PSS_PSS_SHA512 = 0x080b

    # Legacy algorithms
    RSA_PKCS1_SHA1 = 0x0201
    ECDSA_SHA1 = 0x0203


class HeartbeatMode(Hex1Enum):
    PEER_ALLOWED_TO_SEND = 1
    PEER_NOT_ALLOWED_TO_SEND = 2


class CertificateType(Hex1Enum):
    X509 = 0
    OPENPGP = 1
    RAW_PUBLIC_KEY = 2
    CT_1609DOT2 = 3


class PskKeyExchangeMode(Hex1Enum):
    PSK_KE = 0
    PSK_DHE_KE = 1


#-----------------------------------------------------------------------
# Extra non-IANA types registered here for simplicity
#-----------------------------------------------------------------------

class TLSVersion(Hex2Enum):
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304
