import typing

from siotls.iana import ContentType
from siotls.utils import RegistryMeta


class Content(metaclass=RegistryMeta):
    _registry_key = '_content_registry'
    _content_registry: typing.ClassVar = {}

    content_type: ContentType
    can_fragment: bool

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Content in cls.__bases__:
            cls._content_registry[cls.content_type] = cls

    @classmethod
    def get_parser(abc, content_type):
        try:
            return abc[ContentType(content_type)]
        except ValueError as exc:
            raise alerts.DecodeError(*exc.args) from exc


from . import alerts
from .application_data import ApplicationData
from .change_cipher_spec import ChangeCipherSpec
from .handshakes import Handshake
from .heartbeat import Heartbeat
