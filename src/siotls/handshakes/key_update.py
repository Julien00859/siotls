from dataclasses import dataclass
from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


@dataclass(init=False)
class KeyUpdate(Handshake, SerializableBody):
    msg_type = HandshakeType.KEY_UPDATE
    ...
