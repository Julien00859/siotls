from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, TooMuchData
from . import Extension


class SignedCertificateTimestamp(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}

    # The mere presence of the extension is enough
    _struct = ""

    def __init__(self):
        pass

    @classmethod
    def parse_body(cls, data):
        if data:
            msg = f"Expected end of stream but {len(data)} bytes remain."
            raise TooMuchData(msg)
        return cls()

    def serialize(self):
        return b''
