import dataclasses

from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerializableBody

from . import Extension


@dataclasses.dataclass(init=False)
class SignedCertificateTimestamp(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.CERTIFICATE,
        HandshakeType.CERTIFICATE_REQUEST
    )

    # The mere presence of the extension is enough
    _struct = ""

    def __init__(self):
        pass

    @classmethod
    def parse_body(cls, stream):  # noqa: ARG003
        return cls()

    def serialize(self):
        return b''
