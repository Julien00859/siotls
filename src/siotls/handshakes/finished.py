from dataclasses import dataclass
from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


@dataclass(init=False)
class Finished(Handshake, SerializableBody):
    msg_type = HandshakeType.FINISHED
    ...
