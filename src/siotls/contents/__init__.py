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
        try:
            return _content_registry[ContentType(content_type)]
        except ValueError as exc:
            raise DecodeError() from exc


# ruff: noqa: F401, E402
from .change_cipher_spec import ChangeCipherSpec
from .alerts import Alert, DecodeError
from .handshakes import Handshake
from .application_data import ApplicationData
from .heartbeat import Heartbeat
