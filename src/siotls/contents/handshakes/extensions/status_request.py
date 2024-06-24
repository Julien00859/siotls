import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import CertificateStatusType, ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Extension

_status_request_registry = {}

@dataclasses.dataclass(init=False)
class CertificateStatusRequest(Extension, SerializableBody):
    extension_type = ExtensionType.STATUS_REQUEST
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.CERTIFICATE_REQUEST
    )

    _struct = textwrap.dedent("""
        struct {
            CertificateStatusType status_type;
            select (status_type) {
                case 0x01: OCSPStatusRequest;
            } request;
        } CertificateStatusRequest;
    """).strip('\n')
    status_type: CertificateStatusType

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and CertificateStatusRequest in cls.__bases__:
            _status_request_registry[cls.status_type] = cls

    @classmethod
    def parse_body(abc, stream, **kwargs):
        status_type = stream.read_int(1)
        try:
            cls = _status_request_registry[CertificateStatusType(status_type)]
        except ValueError as exc:
            # Unlike for ServerName, nothing states how to process
            # unknown certificate status types, crash for now
            raise alerts.UnrecognizedName(*exc.args) from exc
        return cls.parse_bodybody(stream, **kwargs)

    def serialize_body(self):
        return b''.join([
            self.status_type.to_bytes(1, 'big'),
            self.serialize_bodybody(),
        ])


@dataclasses.dataclass(init=False)
class OCSPStatusRequest(CertificateStatusRequest):
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
    def parse_bodybody(cls, stream, **kwargs):  # noqa: ARG003
        responder_id_list = stream.read_listvar(2, 2)
        request_extension = stream.read_var(2)
        return cls(responder_id_list, request_extension)

    def serialize_bodybody(self):
        serialized_responder_id_list = b''.join([
            b''.join([len(responder_id).to_bytes(2, 'big'), responder_id])
            for responder_id in self.responder_id_list
        ])

        return b''.join([
            len(serialized_responder_id_list).to_bytes(2, 'big'),
            serialized_responder_id_list,
            len(self.request_extensions).to_bytes(2, 'big'),
            self.request_extensions,
        ])



_status_registry = {}

@dataclasses.dataclass(init=False)
class CertificateStatus(Extension, SerializableBody):
    extension_type = ExtensionType.STATUS_REQUEST
    _handshake_types = (
        HandshakeType.CERTIFICATE,
    )

    _struct = textwrap.dedent("""
        struct {
            CertificateStatusType status_type;
            select (status_type) {
                case ocsp: OCSPResponse;
            } response;
        } CertificateStatus;
    """).strip('\n')
    status_type: CertificateStatusType

    def __init_subclass__(cls, *, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and CertificateStatus in cls.__bases__:
            _status_registry[cls.status_type] = cls

    @classmethod
    def parse_body(abc, stream, **kwargs):
        status_type = stream.read_int(1)
        try:
            cls = _status_registry[CertificateStatusType(status_type)]
        except ValueError as exc:
            # Unlike for ServerName, nothing states how to process
            # unknown certificate status types, crash for now
            raise alerts.UnrecognizedName(*exc.args) from exc
        return cls.parse_bodybody(stream, **kwargs)

    def serialize_body(self):
        return b''.join([
            self.status_type.to_bytes(1, 'big'),
            self.serialize_bodybody(),
        ])

class OCSPStatus(CertificateStatus):
    status_type = CertificateStatusType.OCSP

    _struct = textwrap.dedent("""
        opaque OCSPResponse<1..2^24-1>;
    """).strip('\n')
    ocsp_response: bytes

    def __init__(self, ocsp_response):
        self.ocsp_response = ocsp_response

    @classmethod
    def parse_bodybody(cls, stream):
        return cls(stream.read_var(3))

    def serialize_bodybody(self):
        return b''.join([
            len(self.ocsp_response).to_bytes(3, 'big'),
            self.ocsp_response,
        ])
