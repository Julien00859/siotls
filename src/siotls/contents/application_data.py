import dataclasses
import textwrap

from siotls.iana import ContentType
from siotls.serial import Serializable

from . import Content


@dataclasses.dataclass(init=False)
class ApplicationData(Content, Serializable):
    content_type = ContentType.APPLICATION_DATA
    can_fragment = True

    _struct = textwrap.dedent("""
        opaque content_data[TLSPlaintext.length];
    """).strip('\n')
    content_data: bytes

    def __init__(self, data):
        self.content_data = data

    @classmethod
    def parse(cls, stream, **kwargs):  # noqa: ARG003
        return cls(stream.read())

    def serialize(self):
        return self.content_data
