from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class EarlyData(Extension, SerializableBody):
    extension_type = ExtensionType.EARLY_DATA
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS, HT.NEW_SESSION_TICKET}
