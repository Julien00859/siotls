import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.contents.handshakes.extensions import Extension
from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerialIO, SerializableBody

from . import Handshake


@dataclasses.dataclass(init=False)
class CertificateRequest(Handshake, SerializableBody):
    msg_type = HandshakeType.CERTIFICATE_REQUEST
    _struct = textwrap.dedent("""
        struct {
            opaque certificate_request_context<0..2^8-1>;
            Extension extensions<0..2^16-1>;
        } CertificateRequest;
    """)
    certificate_request_context: bytes
    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, certificate_request_context, extensions):
        self.certificate_request_context = certificate_request_context
        self.extensions = {ext.extension_type: ext for ext in extensions}
        if ExtensionType.SIGNATURE_ALGORITHMS not in self.extensions:
            e =(f"{ExtensionType.SIGNATURE_ALGORITHMS} is a mandatory "
                f"extension with {type(self)}")
            raise ValueError(e)

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        certificate_request_context = stream.read_var(1)

        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(
                list_stream, handshake_type=HandshakeType.CERTIFICATE_REQUEST)
            extensions.append(extension)

        try:
            return cls(certificate_request_context, extensions)
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc

    def serialize_body(self):
        extensions = b''.join(ext.serialize() for ext in self.extensions.values())

        return b''.join([
            len(self.certificate_request_context).to_bytes(1, 'big'),
            self.certificate_request_context,
            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])
