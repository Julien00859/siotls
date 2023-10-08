import textwrap
from dataclasses import dataclass
from siotls.iana import ExtensionType, HandshakeType as HT, NamedGroup
from siotls.serial import SerializableBody
from siotls.utils import try_cast
from . import Extension


@dataclass(init=False)
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
    def parse_body(cls, stream):
        named_group_list = [
            try_cast(NamedGroup, named_group)
            for named_group in stream.read_listint(2, 2)
        ]
        return cls(named_group_list)

    def serialize_body(self):
        return b''.join([
            (len(self.named_group_list) * 2).to_bytes(2, 'big'),
            *[
                named_group.to_bytes(2, 'big')
                for named_group in self.named_group_list
            ]
        ])
