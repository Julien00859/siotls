import collections
import textwrap
from siotls.iana import ExtensionType
from siotls.serial import Serializable, SerializableBody, SerialIO


_extension_registry = {}

class Extension(Serializable):
    _handshake_types: collections.abc.Container
    _struct = textwrap.dedent("""
        struct {
            ExtensionType extension_type;
            uint16 extension_length;
            select (Extension.extension_type) {
                case 0x0000: ServerNameList;
                case 0x0001: MaxFragmentLength;
                case 0x0005: CertificateStatusRequest;
                case 0x000a: SupportedGroups;
                case 0x000d: SignatureAlgorithms;
                case 0x000e: UseSrtp;
                case 0x000f: Heartbeat;
                case 0x0010: ApplicationLayerProtocolNegotiation;
                case 0x0012: SignedCertificateTimestamp;
                case 0x0013: ClientCertificateType;
                case 0x0014: ServerCertificateType;
                case 0x0015: Padding;
                case 0x0029: PreSharedKey;
                case 0x002a: EarlyData;
                case 0x002b: SupportedVersions;
                case 0x002c: Cookie;
                case 0x002d: PskKeyExchangeModes;
                case 0x002f: CertificateAuthorities;
                case 0x0030: OidFilters;
                case 0x0031: PostHandshakeAuth;
                case 0x0032: SignatureAlgorithmsCert;
                case 0x0033: KeyShare;
                case      _: UnknownExtension;
            }
        } Extension;
    """).strip('\n')
    extension_type: ExtensionType | int

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and Extension in cls.__bases__:
            _extension_registry[cls.extension_type] = cls

    @classmethod
    def parse(abc, data):
        stream = SerialIO(data)
        extension_type = stream.read_int(2)
        try:
            cls = _extension_registry[ExtensionType(extension_type)]
        except ValueError:
            cls = type('UnknownExtension', (UnknownExtension,), {
                '_struct': UnknownExtension._struct,
                'extension_type': extension_type,
            })
        self = cls.parse_body(stream.read_var(2))

        stream.assert_eof()

        return self

    def serialize(self):
        extension_data = self.serialize_body()
        return b''.join([
            self.extension_type.to_bytes(2, 'big'),
            len(extension_data).to_bytes(2, 'big'),
            extension_data,
        ])


class UnknownExtension(Extension, SerializableBody, register=False):
    _handshake_types = type("Everything", (), {'__contains__': lambda self, item: True})()

    _struct = textwrap.dedent("""
        struct {
            opaque extension_data[Extension.extension_length];
        } UnknownExtension;
    """).strip('\n')
    extension_data: bytes

    def __init__(self, extension_data):
        self.extension_data = extension_data

    @classmethod
    def parse_body(cls, data):
        return cls(data)

    @classmethod
    def serialize_body(self):
        return self.extension_data


# ruff: isort: off
from .server_name import ServerName, HostName, ServerNameList
from .max_fragment_length import MaxFragmentLength
from .status_request import CertificateStatusRequest, OCSPStatusRequest
from .supported_groups import SupportedGroups
from .signature_algorithms import SignatureAlgorithms, SignatureAlgorithmsCert
from .use_srtp import UseSRTP
from .heartbeat import Heartbeat
from .application_layer_protocol_negotiation import ApplicationLayerProtocolNegotiation
from .signed_certificate_timestamp import SignedCertificateTimestamp
from .client_certificate_type import ClientCertificateType
from .server_certificate_type import ServerCertificateType
from .padding import Padding
from .pre_shared_key import PreSharedKey
from .early_data import EarlyData
from .supported_versions import SupportedVersions
from .cookie import Cookie
from .psk_key_exchange_modes import PskKeyExchangeModes
from .certificate_authorities import CertificateAuthorities
from .oid_filters import OidFilters
from .post_handshake_auth import PostHandshakeAuth
from .key_share import KeyShare