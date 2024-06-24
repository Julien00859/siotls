import dataclasses
import textwrap

from siotls.iana import ALPNProtocol, ExtensionType, HandshakeType
from siotls.serial import SerializableBody
from siotls.utils import try_cast

from . import Extension


@dataclasses.dataclass(init=False)
class ALPN(Extension, SerializableBody):
    extension_type = ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.ENCRYPTED_EXTENSIONS
    )

    _struct = textwrap.dedent("""
        opaque ProtocolName<1..2^8-1>;
        struct {
            ProtocolName protocol_name_list<2..2^16-1>
        } ProtocolNameList;
    """).strip()
    protocol_name_list: list[ALPNProtocol | str]

    def __init__(self, protocol_name_list):
        self.protocol_name_list = protocol_name_list

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        protocol_name_list = [
            try_cast(ALPNProtocol, protocol.decode())
            for protocol in stream.read_listvar(2, 1)
            if all(ord(' ') <= char <= ord('~') for char in protocol)  # skip GREASE
        ]
        return cls(protocol_name_list)

    def serialize_body(self):
        protocol_name_list = b''.join([
            len(proto_bytes := proto.encode()).to_bytes(1, 'big') + proto_bytes
            for proto in self.protocol_name_list
        ])

        return b''.join([
            len(protocol_name_list).to_bytes(2, 'big'),
            protocol_name_list,
        ])
