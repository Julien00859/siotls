from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class PreSharedKey(Extension, SerializableBody):
    extension_type = ExtensionType.PRE_SHARED_KEY
    _handshake_types = {HT.CLIENT_HELLO, HT.SERVER_HELLO}
