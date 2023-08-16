import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT
from siotls.serial import SerializableBody, SerialIO
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
    def parse_body(cls, data):
        stream = SerialIO(data)

        protocol_name_list = []
        list_length = stream.read_int(2)
        while list_length > 0:
            protocol_name_list.append(stream.read_var(1, limit=list_length))
            list_length -= len(protocol_name_list[-1]) + 1

        stream.assert_eof()
        return cls(protocol_name_list)

    def serialize_body(self):
        return b''.join([
            len(self.protocol_name_list).to_bytes(2, 'big'),
            *self.protocol_name_list,
        ])
