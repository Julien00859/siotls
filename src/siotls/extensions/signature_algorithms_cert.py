from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class SignatureAlgorithmsCert(Extension, SerializableBody):
    extension_type = ExtensionType.SIGNATURE_ALGORITHMS_CERT
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}
