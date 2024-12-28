import dataclasses
import textwrap

from siotls.contents import alerts
from siotls.iana import ExtensionType, HandshakeType, NamedGroup
from siotls.serial import SerializableBody
from siotls.utils import try_cast

from . import Extension


@dataclasses.dataclass(init=False)
class SupportedGroups(Extension, SerializableBody):
    extension_type = ExtensionType.SUPPORTED_GROUPS
    _handshake_types = (
        HandshakeType.CLIENT_HELLO,
        HandshakeType.ENCRYPTED_EXTENSIONS
    )

    _struct = textwrap.dedent("""
        struct {
            NamedGroup named_group_list<2..2^16-1>;
        } NamedGroupList;
    """).strip()

    named_group_list: list[NamedGroup | int]

    def __init__(self, named_group_list):
        if len(named_group_list) != len(set(named_group_list)):
            e = "the list cannot have duplicates"
            raise ValueError(e)
        self.named_group_list = named_group_list

    @classmethod
    def parse_body(cls, stream, **kwargs):  # noqa: ARG003
        named_group_list = [
            try_cast(NamedGroup, named_group)
            for named_group in stream.read_listint(2, 2)
        ]
        try:
            return cls(named_group_list)
        except ValueError as exc:
            raise alerts.IllegalParameter(*exc.args) from exc

    def serialize_body(self):
        return b''.join([
            (len(self.named_group_list) * 2).to_bytes(2, 'big'),
            *[
                named_group.to_bytes(2, 'big')
                for named_group in self.named_group_list
            ]
        ])
