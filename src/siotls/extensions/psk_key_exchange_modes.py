from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class PskKeyExchangeModes(Extension, SerializableBody):
    extension_type = ExtensionType.PSK_KEY_EXCHANGE_MODES
    _handshake_types = {HT.CLIENT_HELLO}
