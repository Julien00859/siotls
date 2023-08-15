from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class ServerCertificateType(Extension, SerializableBody):
    extension_type = ExtensionType.SERVER_CERTIFICATE_TYPE
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}
