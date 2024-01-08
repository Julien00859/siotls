import dataclasses
import textwrap
from siotls.iana import HandshakeType, HandshakeType_, ExtensionType
from siotls.serial import Serializable, SerializableBody
from ... import alerts
from siotls.utils import try_cast


_extension_registry = {}

@dataclasses.dataclass(init=False)
class Extension(Serializable):
    # TODO: could be tuple[HandshakeType | HandshakeType_]
    _handshake_types: set[HandshakeType] | list[HandshakeType | HandshakeType_]
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
            registry = _extension_registry.setdefault(cls.extension_type, {})
            for handshake_type in cls._handshake_types:
                htname = handshake_type.name
                existing_cls = registry.setdefault(htname, cls)
                if existing_cls != cls:
                    etname = cls.extension_type.name
                    e =(f"Cannot register {cls} at pair ({etname}, {htname}), "
                        f"another exist already: {existing_cls}")
                    raise ValueError(e)

    @classmethod
    def parse(abc, stream, *, handshake_type):
        extension_type = try_cast(ExtensionType, stream.read_int(2))

        if registry := _extension_registry.get(extension_type):
            try:
                cls = registry.get(HandshakeType_.ANY.name) or registry[handshake_type.name]
            except KeyError:
                e = (f"cannot receive extension {extension_type!r} "
                     f"with handshake {handshake_type.name}")
                raise alerts.IllegalParameter(e)

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


@dataclasses.dataclass(init=False)
class UnknownExtension(SerializableBody):
    _handshake_types = {HandshakeType_.ANY}

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


# ruff: noqa: F401, E402
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
from .key_share import KeyShareRequest, KeyShareResponse, KeyShareRetry
