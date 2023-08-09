from . import alerts
from .iana import ExtensionType, HandshakeType as HT, NameType, MaxFragmentLength, CertificateStatusType
from .serial import Serializable, SerialIO


extension_registry = {}

class Extension(Serializable):
    # struct {
    #     ExtensionType extension_type;
    #     opaque extension_data<0..2^16-1>;
    # } Extension;
    extension_type: ExtensionType
    handshake_types: set

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Extension in cls.__bases__:
            extension_registry[cls.extension_type] = cls

    @classmethod
    def parse(abc, data):
        stream = SerialIO(data)
        extension_type = stream.read_int(2)
        try:
            cls = extension_registry[ExtensionType(extension_type)]
        except ValueError:
            return UnknownExtension(extension_type, stream.read())
        self = cls.parse(stream.read_var(2))

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        return self

    def serialize(self):
        extension_data = extension_registry[self.extension_type].serial()
        return b''.join([
            self.extension_type.to_bytes(2, 'big'),
            len(extension_data).to_bytes(2, 'big'),
            extension_data,
        ])


class UnknownExtension(Serializable):
    extension_type: int
    extension_data: bytes

    def __init__(self, extension_type, extension_data):
        self.extension_type = extension_type
        self.extension_data = extension_data

    @classmethod
    def parse(cls, data):
        raise NotImplementedError("Cannot parse an unknown extension.")

    @classmethod
    def serialize(self):
        return b''.join([
            self.extension_type.to_bytes(2, 'big'),
            len(self.extension_data).to_bytes(2, 'big'),
            self.extension_data,
        ])


#-----------------------------------------------------------------------
# Server Name
#-----------------------------------------------------------------------
server_name_registry = {}

class ServerNameList(Extension):
    extension_type = ExtensionType.SERVER_NAME
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    # struct {
    #     ServerName server_name_list<1..2^16-1>
    # } ServerNameList;
    server_name_list: list['ServerName']

    def __init__(self, server_name_list):
        self.server_name_list = server_name_list

    @classmethod
    def parse(cls, data):
        stream = SerialIO(data)

        server_name_list = []
        remaining = stream.read_int(2)
        while remaining > 0:
            with stream.lookahead():
                # we don't know the length of each individual element
                # before parsing them, introspect the data to determine
                # it
                name_type = stream.read_int(1, limit=remaining)
                server_name_length = 1  # name_type
                match name_type:
                    case NameType.HOST_NAME:
                        server_name_length += 2 + stream.read_int(2, limit=remaining - 1)
                    case _:
                        # unknown type, must assume it is the last element
                        server_name_length = remaining
            server_name_list.append(
                ServerName.parse(stream.read_exactly(server_name_length, limit=remaining))
            )
            remaining -= server_name_length
        if remaining < 0:
            raise RuntimeError(f"buffer overflow while parsing {data}")

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        return cls(server_name_list)

    def serialize(self):
        stream = SerialIO()

        for name_type, *opaque in self.server_name_list:
            stream.write_int(1, name_type)
            match name_type:
                case NameType.HOST_NAME:
                    host_name, = opaque
                    stream.write_var(2, host_name)
                case _:
                    raise KeyError(f"missing parser for {name_type}")

        return stream.getvalue()


class ServerName(Serializable):
    # struct {
    #     NameType name_type;
    #     select (name_type) {
    #         case host_name: HostName;
    #     } name;
    # } ServerName;
    #
    # enum {
    #     host_name(0), (255)
    # } NameType;
    name_type: NameType

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if ServerName in cls.__bases__:
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
        return cls.parse(stream.read())

    def serialize(self):
        return b''.join([
            self.name_type.to_bytes(1, 'big'),
            server_name_registry[self.name_type].serial(),
        ])


class HostName(ServerName):
    name_type = NameType.HOST_NAME
    # opaque HostName<1..2^16-1>;
    host_name: bytes

    def __init__(self, host_name):
        self.host_name = host_name

    @classmethod
    def parse(cls, data):
        stream = SerialIO(data)
        host_name = stream.read_var(2)
        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")
        return cls(host_name)

    def serialize(self):
        return b''.join([
            len(self.host_name).to_bytes(2, 'big'),
            self.host_name,
        ])


#-----------------------------------------------------------------------
# Max Fragment Length
#-----------------------------------------------------------------------

class MaxFragmentLength(Extension):
    extension_type = ExtensionType.MAX_FRAGMENT_LENGTH
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    # enum{
    #     2^9(1), 2^10(2), 2^11(3), 2^12(4), (255)
    # } MaxFragmentLength;
    max_fragment_length: MaxFragmentLength

    def __init__(self, max_fragment_length):
        self.max_fragment_length = max_fragment_length

    @classmethod
    def parse(cls, data):
        if len(data) != 1:
            raise ValueError(f"Expected exactly 1 byte but found {len(data)}")
        max_fragment_length = int.from_bytes(data[0], 'big')
        try:
            max_fragment_length = MaxFragmentLength(max_fragment_length)
        except ValueError as exc:
            raise alerts.IllegalParameter() from exc
        return cls(max_fragment_length)

    def serialize(self):
        return self.max_fragment_length.to_bytes(1, 'big')


#-----------------------------------------------------------------------
# Status Request
#-----------------------------------------------------------------------
status_request_registry = {}

class StatusRequest(Extension):
    extension_type = ExtensionType.STATUS_REQUEST
    handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}

    # struct {
    #     CertificateStatusType status_type;
    #     select (status_type) {
    #         case ocsp: OCSPStatusRequest;
    #     } request;
    # } CertificateStatusRequest;
    #
    # enum { ocsp(1), (255) } CertificateStatusType;
    status_type: CertificateStatusType

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if StatusRequest in cls.__bases__:
            status_request_registry[cls.extension_type] = cls

    @classmethod
    def parse(abc, data):
        stream = SerialIO(data)

        status_type = stream.read_int(1)
        try:
            status_type = CertificateStatusType(status_type)
        except ValueError as exc:
            # Unlike for ServerName, nothing states how to process
            # unknown certificate status types, crash for now
            raise alerts.UnrecognizedName() from exc

        return status_request_registry[status_type].parse(stream.read())

    def serialize(self):
        return b''.join([
            self.status_type.to_bytes(1, 'big'),
            status_request_registry[self.status_type].serial(),
        ])


class OCSPStatusRequest(StatusRequest):
    status_type = CertificateStatusType.OCSP

    # struct {
    #     ResponderID responder_id_list<0..2^16-1>;
    #     Extensions  request_extensions;
    # } OCSPStatusRequest;
    #
    # opaque ResponderID<1..2^16-1>;
    # opaque Extensions<0..2^16-1>;
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




class SupportedGroups(Extension):
    extension_type = ExtensionType.SUPPORTED_GROUPS
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class SignatureAlgorithms(Extension):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    handshake_types = {HT.CLIENT_HELLO}


class UseSRTP(Extension):
    extension_type = ExtensionType.USE_SRTP
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class Heartbeat(Extension):
    extension_type = ExtensionType.HEARTBEAT
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class ApplicationLayerProtocolNegotiation(Extension):
    extension_type = ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class SignedCertificateTimestamp(Extension):
    extension_type = ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}


class ClientCertificateType(Extension):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class ServerCertificateType(Extension):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}


class Padding(Extension):
    extension_type = ExtensionType.PADDING
    handshake_types = {HT.CLIENT_HELLO}


class PreSharedKey(Extension):
    extension_type = ExtensionType.PRE_SHARED_KEY
    handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}


class EarlyData(Extension):
    extension_type = ExtensionType.EARLY_DATA
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS, HT.NEW_SESSION_TICKET}


class SupportedVersions(Extension):
    extension_type = ExtensionType.SUPPORTED_VERSIONS
    handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}


class Cookie(Extension):
    extension_type = ExtensionType.COOKIE
    handshake_types = {HT.CLIENT_HELLO}


class PskKeyExchangeModes(Extension):
    extension_type = ExtensionType.PSK_KEY_EXCHANGE_MODES
    handshake_types = {HT.CLIENT_HELLO}


class CertificateAuthorities(Extension):
    extension_type = ExtensionType.CERTIFICATE_AUTHORITIES
    handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}


class OidFilters(Extension):
    extension_type = ExtensionType.OID_FILTERS
    handshake_types = {HT.CERTIFICATE_REQUEST}


class PostHandshakeAuth(Extension):
    extension_type = ExtensionType.POST_HANDSHAKE_AUTH
    handshake_types = {HT.CLIENT_HELLO}


class SignatureAlgorithmsCert(Extension):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS_CERT
    handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}


class KeyShare(Extension):
    extension_type = ExtensionType.KEY_SHARE
    handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}

