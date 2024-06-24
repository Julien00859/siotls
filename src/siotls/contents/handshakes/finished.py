import dataclasses
import textwrap

from siotls.iana import HandshakeType
from siotls.serial import SerializableBody

from . import Handshake


@dataclasses.dataclass(init=False)
class Finished(Handshake, SerializableBody):
    msg_type = HandshakeType.FINISHED
    _struct = textwrap.dedent("""
        struct {
            opaque verify_data[Hash.length];
        } Finished;
    """).strip('\n')

    verify_data: bytes

    def __init__(self, verify_data):
        self.verify_data = verify_data

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        return cls(stream.read())
        # would be nice:
        # return cls(stream.read_exactly(connection._cipher.digestmod.digest_size))

    def serialize_body(self):
        return self.verify_data
