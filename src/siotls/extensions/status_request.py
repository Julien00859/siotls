import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, CertificateStatusType
from siotls.serial import Serializable, SerializableBody, SerialIO
from . import Extension
from ..contents import alerts


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
    def parse_body(abc, data):
        stream = SerialIO(data)

        status_type = stream.read_int(1)
        try:
            status_type = CertificateStatusType(status_type)
        except ValueError as exc:
            # Unlike for ServerName, nothing states how to process
            # unknown certificate status types, crash for now
            raise alerts.UnrecognizedName() from exc

        return _status_request_registry[status_type].parse(stream.read())

    def serialize_body(self):
        return b''.join([
            self.status_type.to_bytes(1, 'big'),
            _status_request_registry[self.status_type].serial(),
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

        stream.assert_eof()

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
