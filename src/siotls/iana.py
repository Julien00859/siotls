import enum

try:
    from enum import StrEnum
except ImportError:
    from siotls._vendor import StrEnum


class Hex1Enum(enum.IntEnum):
    """ An integer on 1 byte with hexadecimal representation. """
    def __repr__(self):
        return f'<{type(self).__name__}.{self.name}: {self.value} (0x{self.value:02x})>'


class Hex2Enum(enum.IntEnum):
    """ An integer on 2 bytes with hexadecimal representation. """
    def __repr__(self):
        return f'<{type(self).__name__}.{self.name}: {self.value} (0x{self.value:04x})>'


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


class AlertLevel(Hex1Enum):
    WARNING = 1
    FATAL = 2


class ALPNProtocol(StrEnum):
    HTTP_0_9 = "http/0.9"
    HTTP_1_0 = "http/1.0"
    HTTP_1_1 = "http/1.1"
    SPDY_1 = "spdy/1"
    SPDY_2 = "spdy/2"
    SPDY_3 = "spdy/3"
    TURN = "stun.turn"
    STUN = "stun.nat-discovery"
    HTTP_2 = "h2"
    HTTP_2_TCP = "h2c"
    WebRTC = "webrtc"
    cWebRTC = "c-webrtc"  # noqa: N815
    FTP = "ftp"
    IMAP = "imap"
    POP3 = "pop3"
    ManageSieve = "managesieve"
    CoAP = "coap"
    XMPP_client = "xmpp-client"
    XMPP_server = "xmpp-server"
    acme_tls_1 = "acme-tls/1"
    MQTT = "mqtt"
    DNS_over_TLS = "dot"
    NTSKE_1 = "ntske/1"
    SunRPC = "sunrpc"
    HTTP_3 = "h3"
    SMB2 = "smb"
    IRC = "irc"
    NNTP_reading = "nntp"
    NNTP_transit = "nnsp"
    DoQ = "doq"
    SIP = "sip/2"
    TDS_8_0 = "tds/8.0"
    DICOM = "dicom"


class CertificateStatusType(Hex1Enum):
    OCSP = 1


class CertificateType(Hex1Enum):
    X509 = 0
    OPENPGP = 1
    RAW_PUBLIC_KEY = 2
    CT_1609DOT2 = 3


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


class ExtensionType(Hex2Enum):
    SERVER_NAME = 0
    MAX_FRAGMENT_LENGTH = 1
    STATUS_REQUEST = 5
    SUPPORTED_GROUPS = 10
    SIGNATURE_ALGORITHMS = 13  # CertificateVerify
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
    SIGNATURE_ALGORITHMS_CERT = 50  # Certificate signature
    KEY_SHARE = 51

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

class HandshakeType_(Hex1Enum):  # noqa: N801
    ANY = -1  # for when an extension can be present in any handshake
    HELLO_RETRY_REQUEST = 2


class HeartbeatMessageType(Hex1Enum):
    heartbeat_request = 1
    heartbeat_response = 2


class HeartbeatMode(Hex1Enum):
    PEER_ALLOWED_TO_SEND = 1
    PEER_NOT_ALLOWED_TO_SEND = 2

class MaxFragmentLengthCode(Hex1Enum):
    MAX_512 = 1
    MAX_1024 = 2
    MAX_2048 = 3
    MAX_4096 = 4

    def to_octets(self):
        return MaxFragmentLengthOctets[self.name]


class MaxFragmentLengthOctets(enum.IntEnum):
    MAX_512 = 512
    MAX_1024 = 1024
    MAX_2048 = 2048
    MAX_4096 = 4096
    MAX_16384 = 16384

    def to_code(self):
        return MaxFragmentLengthCode[self.name]


class NamedGroup(Hex2Enum):
    # ELLIPTIC Curve Groups (ECDHE)
    secp256r1 = 0x0017
    secp384r1 = 0x0018
    secp521r1 = 0x0019
    x25519 = 0x001D
    x448 = 0x001E

    # Finite Field Groups (DHE)
    ffdhe2048 = 0x0100
    ffdhe3072 = 0x0101
    ffdhe4096 = 0x0102
    ffdhe6144 = 0x0103
    ffdhe8192 = 0x0104


class NameType(Hex1Enum):
    HOST_NAME = 0


class PskKeyExchangeMode(Hex1Enum):
    PSK_KE = 0
    PSK_DHE_KE = 1


class SignatureScheme(Hex2Enum):
    # RSASSA-PKCS1-v1_5 algorithms
    rsa_pkcs1_sha256 = 0x0401
    rsa_pkcs1_sha384 = 0x0501
    rsa_pkcs1_sha512 = 0x0601

    # ECDSA algorithms
    ecdsa_secp256r1_sha256 = 0x0403
    ecdsa_secp384r1_sha384 = 0x0503
    ecdsa_secp521r1_sha512 = 0x0603

    # RSASSA-PSS algorithms with public key OID rsaEncryption
    rsa_pss_rsae_sha256 = 0x0804
    rsa_pss_rsae_sha384 = 0x0805
    rsa_pss_rsae_sha512 = 0x0806

    # EdDSA algorithms
    ed25519 = 0x0807
    ed448 = 0x0808

    # RSASSA-PSS algorithms with public key OID RSASSA-PSS
    rsa_pss_pss_sha256 = 0x0809
    rsa_pss_pss_sha384 = 0x080a
    rsa_pss_pss_sha512 = 0x080b

    # Legacy algorithms
    rsa_pkcs1_sha1 = 0x0201
    ecdsa_sha1 = 0x0203


class TLSVersion(Hex2Enum):
    TLS_1_0 = 0x0301
    TLS_1_1 = 0x0302
    TLS_1_2 = 0x0303
    TLS_1_3 = 0x0304
