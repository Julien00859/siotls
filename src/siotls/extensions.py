import collections.abc
import textwrap
from . import alerts
from .iana import (
    CertificateStatusType,
    ExtensionType,
    HandshakeType as HT,
    MaxFragmentLength,
    NameType,
)
from .serial import Serializable, SerializableBody, SerialIO


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

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

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


#-----------------------------------------------------------------------
# Server Name
#-----------------------------------------------------------------------
server_name_registry = {}

class ServerName(Serializable):
    _struct = textwrap.dedent("""
        struct {
            NameType name_type;
            select (name_type) {
                case host_name: HostName;
            } name;
        } ServerName;

        enum {
            host_name(0x00), (0xff)
        } NameType;
    """).strip('\n')
    name_type: NameType

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and ServerName in cls.__bases__:
            server_name_registry[cls.name_type] = cls

    @classmethod
    def parse(abc, data):
        stream = SerialIO(data)

        name_type = stream.read_int(1)
        try:
            cls = server_name_registry[NameType(name_type)]
        except ValueError as exc:
            # unknown type, can choice to either crash or ignore
            # this extension, crash for now.
            # should be configurable (should it?)
            raise alerts.UnrecognizedName() from exc
        return cls.parse_body(stream.read())

    def serialize(self):
        return b''.join([
            self.name_type.to_bytes(1, 'big'),
            self.serialize_body(),
        ])

class HostName(ServerName, SerializableBody):
    name_type = NameType.HOST_NAME

    _struct = textwrap.dedent("""
        opaque HostName<1..2^16-1>;
    """).strip('\n')
    host_name: bytes

    def __init__(self, host_name):
        self.host_name = host_name

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)
        host_name = stream.read_var(2)
        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")
        return cls(host_name)

    def serialize_body(self):
        return b''.join([
            len(self.host_name).to_bytes(2, 'big'),
            self.host_name,
        ])

class ServerNameList(Extension, SerializableBody):
    extension_type = ExtensionType.SERVER_NAME
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}
    _struct = textwrap.dedent("""
        struct {
            ServerName server_name_list<1..2^16-1>
        } ServerNameList;
    """).strip('\n')

    server_name_list: list[ServerName]

    def __init__(self, server_name_list):
        self.server_name_list = server_name_list

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)

        server_name_list = []
        remaining = stream.read_int(2)
        while remaining > 0:
            with stream.lookahead():
                # we don't know the length of each individual element
                # before parsing them, inspect the data to determine it
                name_type = stream.read_int(1, limit=remaining)
                server_name_length = 1  # name_type
                match name_type:
                    case NameType.HOST_NAME:
                        server_name_length += 2 + stream.read_int(2, limit=remaining - 1)
                    case _:
                        # unknown type, must assume it is the last element
                        server_name_length = remaining

            item_data = stream.read_exactly(server_name_length, limit=remaining)
            remaining -= server_name_length
            server_name_list.append(ServerName.parse(item_data))
        if remaining < 0:
            raise RuntimeError(f"buffer overflow while parsing {data}")

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        return cls(server_name_list)

    def serialize_body(self):
        server_name_list = b''.join([
            server_name.serialize()
            for server_name
            in self.server_name_list
        ])

        return b''.join([
            len(server_name_list).to_bytes(2, 'big'),
            server_name_list
        ])


#-----------------------------------------------------------------------
# Max Fragment Length
#-----------------------------------------------------------------------

class MaxFragmentLength(Extension, SerializableBody):
    extension_type = ExtensionType.MAX_FRAGMENT_LENGTH
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        enum {
            2^9(0x01), 2^10(0x02), 2^11(0x03), 2^12(0x04), (0xff)
        } MaxFragmentLength;
    """).strip('\n')
    max_fragment_length: MaxFragmentLength

    def __init__(self, max_fragment_length):
        self.max_fragment_length = max_fragment_length

    @classmethod
    def parse_body(cls, data):
        if len(data) != 1:
            raise ValueError(f"Expected exactly 1 byte but found {len(data)}")
        max_fragment_length = int.from_bytes(data[0], 'big')
        try:
            max_fragment_length = MaxFragmentLength(max_fragment_length)
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(max_fragment_length)

    def serialize_body(self):
        return self.max_fragment_length.to_bytes(1, 'big')


#-----------------------------------------------------------------------
# Status Request
#-----------------------------------------------------------------------
status_request_registry = {}

class CertificateStatusRequest(Extension, SerializableBody):
    extension_type = ExtensionType.STATUS_REQUEST
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}

    _struct = textwrap.dedent("""
        struct {
            CertificateStatusType status_type;
            select (status_type) {
                case 0x01: OCSPStatusRequest;
            } request;
        } CertificateStatusRequest;
    """).strip('\n')
    status_type: CertificateStatusType

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and CertificateStatusRequest in cls.__bases__:
            status_request_registry[cls.extension_type] = cls

    @classmethod
    def parse_body(abc, data):
        stream = SerialIO(data)

        status_type = stream.read_int(1)
        try:
            status_type = CertificateStatusType(status_type)
        except ValueError as exc:
            # Unlike for ServerName, nothing states how to process
            # unknown certificate status types, crash for now
            raise alerts.UnrecognizedName() from exc

        return status_request_registry[status_type].parse(stream.read())

    def serialize_body(self):
        return b''.join([
            self.status_type.to_bytes(1, 'big'),
            status_request_registry[self.status_type].serial(),
        ])


class OCSPStatusRequest(CertificateStatusRequest, Serializable):
    status_type = CertificateStatusType.OCSP

    _struct = textwrap.dedent("""
        struct {
            ResponderID responder_id_list<0..2^16-1>;
            Extensions  request_extensions;
        } OCSPStatusRequest;

        opaque ResponderID<1..2^16-1>;
        opaque Extensions<0..2^16-1>;
    """).strip('\n')
    responder_id_list: list[bytes]
    request_extensions: bytes

    def __init__(self, responder_id_list, request_extensions):
        self.responder_id_list = responder_id_list
        self.request_extensions = request_extensions

    @classmethod
    def parse(cls, data):
        stream = SerialIO(data)
        responder_id_list = []
        remaining = stream.read_int(2)
        while remaining > 0:
            responder_id = stream.read_var(2, limit=remaining)
            remaining -= 2 - len(responder_id)
            responder_id_list.append(responder_id)
        if remaining < 0:
            raise RuntimeError(f"buffer overflow while parsing {data}")

        request_extension = stream.read_var(2)

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        return cls(responder_id_list, request_extension)

    def serialize(self):
        serialized_responder_id_list = b''.join([
            b''.join([len(responder_id).to_bytes(2, 'big'), responder_id])
            for responder_id in self.responder_id_list
        ])

        return b''.join([
            len(serialized_responder_id_list).to_bytes(2, 'big'),
            serialized_responder_id_list,
            len(self.request_extension).to_bytes(2, 'big'),
            self.request_extensions,
        ])




class SupportedGroups(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_GROUPS
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class SignatureAlgorithms(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    _handshake_types = {HT.CLIENT_HELLO}


class UseSRTP(Extension, SerializableBody):
    extension_type = ExtensionType.USE_SRTP
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class Heartbeat(Extension, SerializableBody):
    extension_type = ExtensionType.HEARTBEAT
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class ApplicationLayerProtocolNegotiation(Extension, SerializableBody):
    extension_type = ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class SignedCertificateTimestamp(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}


class ClientCertificateType(Extension, SerializableBody):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class ServerCertificateType(Extension, SerializableBody):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class Padding(Extension, SerializableBody):
    extension_type = ExtensionType.PADDING
    _handshake_types = {HT.CLIENT_HELLO}


class PreSharedKey(Extension, SerializableBody):
    extension_type = ExtensionType.PRE_SHARED_KEY
    _handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}


class EarlyData(Extension, SerializableBody):
    extension_type = ExtensionType.EARLY_DATA
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS, HT.NEW_SESSION_TICKET}


class SupportedVersions(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_VERSIONS
    _handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}


class Cookie(Extension, SerializableBody):
    extension_type = ExtensionType.COOKIE
    _handshake_types = {HT.CLIENT_HELLO}


class PskKeyExchangeModes(Extension, SerializableBody):
    extension_type = ExtensionType.PSK_KEY_EXCHANGE_MODES
    _handshake_types = {HT.CLIENT_HELLO}


class CertificateAuthorities(Extension, SerializableBody):
    extension_type = ExtensionType.CERTIFICATE_AUTHORITIES
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}


class OidFilters(Extension, SerializableBody):
    extension_type = ExtensionType.OID_FILTERS
    _handshake_types = {HT.CERTIFICATE_REQUEST}


class PostHandshakeAuth(Extension, SerializableBody):
    extension_type = ExtensionType.POST_HANDSHAKE_AUTH
    _handshake_types = {HT.CLIENT_HELLO}


class SignatureAlgorithmsCert(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS_CERT
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}


class KeyShare(Extension, SerializableBody):
    extension_type = ExtensionType.KEY_SHARE
    _handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}

