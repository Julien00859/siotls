from siotls.iana import ContentType


_content_registry = {}

class Content:
    content_type: ContentType
    can_fragment: bool

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Content in cls.__bases__:
            _content_registry[cls.content_type] = cls

    @classmethod
    def get_parser(abc, content_type):
        return _content_registry[ContentType(content_type)]


# ruff: isort: off
from .change_cipher_spec import ChangeCipherSpec
from .alerts import Alert
from .handshakes import Handshake
from .application_data import ApplicationData
from .heartbeat import Heartbeat
