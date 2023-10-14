import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, CertificateStatusType
from siotls.serial import SerializableBody, SerialIO
from ... import alerts
from . import Extension


_status_request_registry = {}

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
            _status_request_registry[cls.extension_type] = cls

    @classmethod
    def parse_body(abc, stream):
        status_type = stream.read_int(1)
        try:
            cls = _status_request_registry[CertificateStatusType(status_type)]
        except ValueError as exc:
            # Unlike for ServerName, nothing states how to process
            # unknown certificate status types, crash for now
            raise alerts.UnrecognizedName() from exc
        return cls.parse_bodybody(stream)

    def serialize_body(self):
        return b''.join([
            self.status_type.to_bytes(1, 'big'),
            self.serialize_bodybody(),
        ])


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
    def parse_bodybody(cls, stream):
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
            len(self.request_extension).to_bytes(2, 'big'),
            self.request_extensions,
        ])
