import textwrap
from siotls.iana import ExtensionType, HandshakeType as HT, NamedGroup
from siotls.serial import SerializableBody, SerialIO
from . import Extension


class SupportedGroups(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_GROUPS
    _handshake_types = {HT.CLIENT_HELLO, HT.ENCRYPTED_EXTENSIONS}

    _struct = textwrap.dedent("""
        struct {
            NamedGroup named_group_list<2..2^16-1>;
        } NamedGroupList;
    """).strip()

    named_group_list: list[NamedGroup | int]

    def __init__(self, named_group_list):
        self.named_group_list = named_group_list

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)

        named_group_list = []
        it = iter(stream.read_var(2))
        for pair in zip(it, it):
            named_group = (pair[0] << 8) + pair[1]
            try:
                named_group_list.append(NamedGroup(named_group))
            except ValueError:
                named_group_list.append(named_group)

        stream.assert_eof()
        return cls(named_group_list)

    def serialize_body(self):
        return b''.join([
            (len(self.named_group_list) * 2).to_bytes(2, 'big'),
            *[
                named_group.to_bytes(2, 'big')
                for named_group in self.named_group_list
            ]
        ])
