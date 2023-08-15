from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class UseSRTP(Extension, SerializableBody):
    extension_type = ExtensionType.USE_SRTP
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}
