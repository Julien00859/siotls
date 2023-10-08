from dataclasses import dataclass
from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake


@dataclass(init=False)
class EndOfEarlyData(Handshake, SerializableBody):
    msg_type = HandshakeType.END_OF_EARLY_DATA
    ...
