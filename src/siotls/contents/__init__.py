"""
TLS defines about a hundred structures, with many of them coming from
extensions.

TLS is an extensible protocole, many of the structures present here are
not defined in :rfc:`8446` (TLS 1.3) but instead defined in other RFCs.
Often a RFC will define a new structure and IANA will grant it a unique
identifier in one of its enumerations. TLS implementations (like siotls)
can choose to ignore that extension or to support it.

siotls tries to parse all structures, but does not necessarely supports
them all, i.e. it is possible that it parses a structure but does
nothing with it. It also stores the structures it doesn't know as opaque
bytes.

The :mod:`siotls.iana` module contains all the IANA enumerations and
values. When the enumeration is for a TLS structure, then there's an
abstract base class named after the enumeration, and as many concrete
classes as there are values inside the enumeration.

For example, the :class:`siotls.iana.ContentType` is an enumeration with
5 values: ``CHANGE_CIPHER_SPEC``, ``ALERT``, ``HANDSHAKE``,
``APPLICATION_DATA``, ``HEARTBEAT``. For those, :class:`Content` is the
abstract base class, and :class:`~change_cipher_spec.ChangeCipherSpec`,
:class:`~alerts.Alert`, :class:`~handshakes.Handshake`,
:class:`~application_data.ApplicationData`, and
:class:`~heartbeat.Heartbeat` are the concrete classes.

Every concrete class is automatically registered inside the abstract
base class it implements, using the enueration value as key:


    >>> siotls.contents.Content[siotls.iana.ContentType.ALERT]
    <class siotls.contents.alerts.Alert>

On the wire the structures are generally serialized as follow:

.. code-block:: python

   b"{type}{length}{structure}"

The way siotls works, it uses the abstract base class to start parsing
the data, to read the ``type`` and ``length``. The abstract base class
then specializes itself into the concrete class for ``type`` and
continues parsing using that concrete class.

    >>> Handshake.parse(SerialIO(b"\\x01" + ...))
    ClientHello(...)  # ClientHello has msg_type=0x01

Pretty much all objects are parsed as above, with the notable exception
of the top-level :class:`Content` object due to its relation with the
Record Protocol (:rfc:`8446#section-5`):

    >>> Content.get_parser(0x16)
    <class siotls.contents.handshakes.Handshake>  # Handshake has content_type=0x16
    >>> _.parse(SerialIO(b"\\x01" + ...))
    ClientHello(...)
"""

import typing

from siotls.iana import ContentType
from siotls.utils import RegistryMeta


class Content(metaclass=RegistryMeta):
    """
    Abstract base class and registry for
    :class:`siotls.iana.ContentType`.

    The *content* is the top-level object of TLS, every message is a
    *content*.
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
