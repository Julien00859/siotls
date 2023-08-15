from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class CertificateAuthorities(Extension, SerializableBody):
    extension_type = ExtensionType.CERTIFICATE_AUTHORITIES
    _handshake_types = {HT.CLIENT_HELLO, HT.CERTIFICATE_REQUEST}
