from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class SignedCertificateTimestamp(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNED_CERTIFICATE_TIMESTAMP
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE, HT.CERTIFICATE_REQUEST}
