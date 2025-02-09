"""
The various data structures defined in :rfc:`8446#` (TLS 1.3) and
related documents.
"""

import typing

from siotls.iana import ContentType
from siotls.utils import RegistryMeta


class Content(metaclass=RegistryMeta):
    """
    Abstract parent class and class registry for all
    :class:`siotls.iana.ContentType` classes.

    >>> Content[ContentType.ALERT] is siotls.contents.alerts.Alert
    True
    """
    _registry_key = '_content_registry'
    _content_registry: typing.ClassVar = {}

    content_type: ContentType
    """ The type of the concrete class. """

    can_fragment: bool
    """ Can this content be fragmented over multiple TLS records? """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Content in cls.__bases__:
            cls._content_registry[cls.content_type] = cls

    @classmethod
    def get_parser(abc, content_type: ContentType | int) -> type[typing.Self]:
        """
        Get the concrete Content class for ``content_type``.

        :raise alerts.DecodeError: When ``content_type``
            is not known.
        """
        try:
            return abc[ContentType(content_type)]
        except ValueError as exc:
            raise alerts.DecodeError(*exc.args) from exc


from . import alerts
from .application_data import ApplicationData
from .change_cipher_spec import ChangeCipherSpec
from .handshakes import Handshake
from .heartbeat import Heartbeat
