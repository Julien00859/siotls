from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class SignatureAlgorithms(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}
