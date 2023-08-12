import textwrap
from .serial import Serializable
from .iana import ContentType


_content_registry = {}

class Content:
    content_type: ContentType

    def __init_subclass__(cls, register=True, **kwargs):
        super().__init_subclass__(**kwargs)
        if register and Content in cls.__bases__:
            _content_registry[cls.content_type] = cls

    @classmethod
    def get_parser(abc, content_type):
        return _content_registry[ContentType(content_type)]


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

from . import alerts  # noqa: F401, E402
from . import handshakes  # noqa: F401, E402
