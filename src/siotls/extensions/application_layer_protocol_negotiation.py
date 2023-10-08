import textwrap
from dataclasses import dataclass
from siotls.iana import ExtensionType, HandshakeType as HT, ALPNProtocol
from siotls.serial import SerializableBody
from siotls.utils import try_cast, is_string
from . import Extension


@dataclass(init=False)
class ApplicationLayerProtocolNegotiation(Extension, SerializableBody):
    extension_type = ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

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
    def parse_body(cls, stream):
        protocol_name_list = [
            try_cast(ALPNProtocol, protocol.decode())
            for protocol in stream.read_listvar(2, 1)
            if is_string(protocol)  # skip GREASE
        ]
        return cls(protocol_name_list)

    def serialize_body(self):
        protocol_name_list = b''.join([
            len(proto).to_bytes(1, 'big') + proto.encode()
            for proto in self.protocol_name_list
        ])

        return b''.join([
            len(protocol_name_list).to_bytes(2, 'big'),
            protocol_name_list,
        ])
