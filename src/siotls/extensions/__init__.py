import textwrap
from typing import Literal
from siotls.iana import HandshakeType, ExtensionType
from siotls.serial import Serializable, SerializableBody


ANY_HANDSHAKE = -1
_extension_registry = {}

class Extension(Serializable):
    _handshake_types: set[HandshakeType | Literal[ANY_HANDSHAKE]]
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
            for handshake_type in cls._handshake_types:
                registry = _extension_registry.setdefault(cls.extension_type, {})
                if registry.get(handshake_type, None) not in (cls, None):
                    msg = ("Cannot register another parser for pair "
                          f"{handshake_type}/{cls.extension_type}")
                    raise ValueError(msg)
                registry[handshake_type] = cls

    @classmethod
    def parse(abc, stream, *, handshake_type):
        extension_type = stream.read_int(2)

        if registry := _extension_registry.get(extension_type):
            try:
                cls = registry.get(ANY_HANDSHAKE) or registry[handshake_type]
            except KeyError:
                raise NotImplementedError("todo")
        else:
            cls = type(
                f'UnkonwnExtension{extension_type}',
                (UnknownExtension, Extension),
                {'extension_type': extension_type},
            )

        extension_length = stream.read_int(2)
        with stream.limit(extension_length):
            return cls.parse_body(stream)

    def serialize(self):
        extension_data = self.serialize_body()
        return b''.join([
            self.extension_type.to_bytes(2, 'big'),
            len(extension_data).to_bytes(2, 'big'),
            extension_data,
        ])


class UnknownExtension(SerializableBody):
    _handshake_types = {ANY_HANDSHAKE}

    _struct = textwrap.dedent("""
        struct {
            opaque extension_data[Extension.extension_length];
        } UnknownExtension;
    """).strip('\n')
    extension_data: bytes

    def __init__(self, extension_data):
        self.extension_data = extension_data

    @classmethod
    def parse_body(cls, stream):
        return cls(stream.read())

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
from .certificate_type import (
    ClientCertificateTypeRequest,
    ClientCertificateTypeResponse,
    ServerCertificateTypeRequest,
    ServerCertificateTypeResponse,
)
from .padding import Padding
from .pre_shared_key import PreSharedKeyRequest, PreSharedKeyResponse, PskIdentity
from .early_data import EarlyData
from .supported_versions import SupportedVersionsRequest, SupportedVersionsResponse
from .cookie import Cookie
from .psk_key_exchange_modes import PskKeyExchangeModes
from .certificate_authorities import CertificateAuthorities
from .oid_filters import OIDFilters, OIDFilter
from .post_handshake_auth import PostHandshakeAuth
from .key_share import KeyShareRequest, KeyShareResponse, KeyShareEntry
