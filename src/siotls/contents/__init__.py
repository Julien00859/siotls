"""
TLS defines about a hundred hierarchized structures, with many of them
coming from extensions.

TLS is an extensible protocole. Many of the structures present here are
not defined in :rfc:`8446` (TLS 1.3) but instead defined in other RFCs.
Often a RFC will define a new structure and IANA will grant it a unique
identifier in one of its enumerations. TLS implementations (like siotls)
can then support that RFC by implementing support for that new
structure, or ignore it if they don't recognize the unique identifier.

The :mod:`siotls.iana` module enumerates and groups those
identifiers. When the enumeration is for a TLS structure, then there's
an abstract base class named after the enumeration, and as many concrete
classes as there are values inside the enumeration.

For example, the :class:`siotls.iana.ContentType` is an enumeration with
5 values: `CHANGE_CIPHER_SPEC`, `ALERT`, `HANDSHAKE`,
`APPLICATION_DATA`, `HEARTBEAT`. So inside this module, we find
:class:`Content`: the abstract base class, and :class:`ChangeCipherSpec`,
:class:`Alert`, :class:`Handshake`, :class:`ApplicationData`, :class:`,
and :class:`Heartbeat`: its concrete classes.

Every concrete class is automatically registered inside the abstract
base class it implements, using the enueration value as key:

    siotls.contents.Content[siotls.iana.ContentType.ALERT] is siotls.contents.alerts.Alert

On the wire the structures are generally serialized as follow:

    b"{type}{length}{structure}"

The way siotls works, it uses the abstract base class to start parsing
the data, to read the ``type`` and ``length``. The abstract base class
then specializes itself into the concrete class for ``type`` and
continues parsing using that concrete class.

    >>> Handshake.parse(SerialIO(b"\x01" + ...))
    ClientHello(...)  # ClientHello has msg_type=0x01
"""

import typing

from siotls.iana import ContentType
from siotls.utils import RegistryMeta


class Content(metaclass=RegistryMeta):
    """
    Abstract parent of all :class:`siotls.iana.ContentType` classes.

    Acts as a registry too:

        >>> Content[ContentType.ALERT]
        <class siotls.contents.alerts.Alert>
    """
    _registry_key = '_content_registry'
    _content_registry: typing.ClassVar = {}

    content_type: ContentType
    """ The unique numeric identifier of the content. """

    can_fragment: bool
    """ Can this content be fragmented over multiple TLS records? """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if Content in cls.__bases__:
            cls._content_registry[cls.content_type] = cls

    @classmethod
    def get_parser(abc, content_type: ContentType | int) -> type[typing.Self]:
        """
        Get the concrete Content class for ``content_type``, when
        ``content_type`` comes from an untrusted source.

        :raise alerts.DecodeError: When ``content_type`` is not known.
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
