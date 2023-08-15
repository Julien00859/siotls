from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class ClientCertificateType(Extension, SerializableBody):
    extension_type = ExtensionType.CLIENT_CERTIFICATE_TYPE
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}
