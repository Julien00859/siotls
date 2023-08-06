import enum
import struct
from typing import Any
from . import alerts
from .iana import ExtensionType, HandshakeType as HT
from .serializable import Serializable, ProtocolIO

extensionmap = {}


class Extension(Serializable):
    # struct {
    #     ExtensionType extension_type;
    #     opaque extension_data<0..2^16-1>;
    # } Extension;
    extension_type: ExtensionType
    handshake_types: set

    def __init_subclass__(cls, *, **kwargs):
        super().__init_subclass__(**kwargs)
        extensionmap[cls.extension_type] = cls

class ServerName(Extension):
    extension_type = ExtensionType.SERVER_NAME
    handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    # struct {
    #     ServerName server_name_list<1..2^16-1>
    # } ServerNameList;
    #
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
    #
    # opaque HostName<1..2^16-1>;
    server_name_list: list[tuple[NameType, Any]]

    def __init__(self, server_name_list):
        self.server_name_list = server_name_list

    @classmethod
    def parse(cls, data):
        stream = ProtocolIO(data)

        server_name_list = []
        server_name_list_length = stream.read_var(2)
        while server_name_list_length:
            name_type = stream.read_int(1)
            try:
                name_type = NameType(name_type)
            except ValueError as exc:
                raise alerts.UnrecognizedName() from exc

            server_name_list_length -= 1
            match name_type:
                case NameType.HOST_NAME:
                    host_name = stream.read_var(2)
                    server_name_list_length -= 2 + len(host_name)
                    server_name_list.append((name_type, host_name))
                case _:
                    raise RuntimeError("unreachable")

        if remaining_data := stream.tell() < len(data):
            raise ValueError(f"Expected end of stream but {remaining_data} bytes remain.")

    def serialize(self):
        stream = ProtocolIO()

        for name_type, opaque in self.server_name_list:
            stream.write_int(1, name_type)
            match name_type:
                case NameType.HOST_NAME:
                    stream.write_var(2, opaque)
                case _:
                    raise RuntimeError("unreachable")

        return stream.tell().to_bytes(2, 'big') + stream.getvalue()


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


class StatusRequest(Extension):
    extension_type = ExtensionType.STATUS_REQUEST
    handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}


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

