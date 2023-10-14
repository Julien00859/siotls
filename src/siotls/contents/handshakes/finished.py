from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


class Finished(Handshake, SerializableBody):
    msg_type = HandshakeType.FINISHED
    ...
