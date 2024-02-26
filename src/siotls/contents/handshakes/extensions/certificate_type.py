import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import CertificateType, ExtensionType, HandshakeType
from siotls.serial import SerializableBody
from siotls.utils import try_cast

from . import Extension


@dataclasses.dataclass(init=False)
class _CertificateTypeRequest(SerializableBody):
    _handshake_types = (HandshakeType.CLIENT_HELLO,)
    certificate_types: list[CertificateType | int]
    _struct = ""  # mute the warning

    def __init__(self, certificate_types):
        if not certificate_types:
            e = "list cannot be empty"
            raise ValueError(e)
        self.certificate_types = certificate_types

    @classmethod
    def parse_body(cls, stream):
        certificate_types = [
            try_cast(CertificateType, ct)
            for ct in stream.read_listint(1, 1)
        ]
        try:
            return cls(certificate_types)
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc

    def serialize_body(self):
        return b''.join([
            len(self.certificate_type).to_bytes(1, 'big'),
            *[ct.to_bytes(1, 'big') for ct in self.certificate_types],
        ])

@dataclasses.dataclass(init=False)
class _CertificateTypeResponse(SerializableBody):
    _handshake_types = (HandshakeType.ENCRYPTED_EXTENSIONS,)
    certificate_type: CertificateType
    _struct = ""  # mute the warning

    def __init__(self, certificate_type):
        self.certificate_type = certificate_type

    @classmethod
    def parse_body(cls, stream):
        try:
            certificate_type = CertificateType(stream.read_int(1))
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc
        return cls(certificate_type)

    @classmethod
    def serialize_body(self):
        return self.certificate_type.to_bytes(1, 'big')

class ClientCertificateTypeRequest(Extension, _CertificateTypeRequest):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE
    _struct = textwrap.dedent("""\
        struct {
            CertificateType client_certificate_types<1..2^8-1>;
        } ClientCertTypeExtension;
    """).strip()

class ClientCertificateTypeResponse(Extension, _CertificateTypeResponse):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE
    _struct = textwrap.dedent("""\
        struct {
            CertificateType client_certificate_type;
        } ClientCertTypeExtension;
    """).strip()

class ServerCertificateTypeRequest(Extension, _CertificateTypeRequest):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE
    _struct = textwrap.dedent("""\
        struct {
            CertificateType server_certificate_types<1..2^8-1>;
        } ServerCertTypeExtension;
    """).strip()

class ServerCertificateTypeResponse(Extension, _CertificateTypeResponse):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE
    _struct = textwrap.dedent("""\
        struct {
            CertificateType server_certificate_type;
        } ServerCertTypeExtension;
    """).strip()
