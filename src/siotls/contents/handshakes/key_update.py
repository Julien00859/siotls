from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


class KeyUpdate(Handshake, SerializableBody):
    msg_type = HandshakeType.KEY_UPDATE
    ...
