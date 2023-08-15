import textwrap
from siotls.iana import ContentType
from siotls.serial import Serializable
from . import Content


class ApplicationData(Content, Serializable):
    content_type = ContentType.APPLICATION_DATA

    _struct = textwrap.dedent("""
        opaque content_data[TLSPlaintext.length];
    """).strip('\n')
    content_data: bytes

    def __init__(self, data):
        self.content_data = data

    @classmethod
    def parse(cls, data):
        return cls(data)

    def serialize(self):
        return self.data
