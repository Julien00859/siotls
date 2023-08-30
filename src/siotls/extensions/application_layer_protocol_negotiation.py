import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody
from . import Extension


class ApplicationLayerProtocolNegotiation(Extension, SerializableBody):
    extension_type = ExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        opaque ProtocolName<1..2^8-1>;
        struct {
            ProtocolName protocol_name_list<2..2^16-1>
        } ProtocolNameList;
    """).strip()
    protocol_name_list: list[bytes]

    def __init__(self, protocol_name_list):
        self.protocol_name_list = protocol_name_list

    @classmethod
    def parse_body(cls, stream):
        protocol_name_list = stream.read_listvar(2, 1)
        return cls(protocol_name_list)

    def serialize_body(self):
        protocol_name_list = b''.join([
            len(proto).to_bytes(1, 'big') + proto
            for proto in self.protocol_name_list
        ])

        return b''.join([
            len(protocol_name_list).to_bytes(2, 'big'),
            protocol_name_list,
        ])
