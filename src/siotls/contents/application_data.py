import dataclasses
import textwrap

from siotls.iana import ContentType
from siotls.serial import Serializable

from . import Content


@dataclasses.dataclass(init=False)
class ApplicationData(Content, Serializable):
    """ The opaque data of/for the protocol that is protected by TLS. """

    content_type = ContentType.APPLICATION_DATA  #:
    can_fragment = True  #:

    _struct = textwrap.dedent("""
        opaque content_data[TLSPlaintext.length];
    """).strip('\n')

    content_data: bytes
    """
    The decrypted data of/for the underlying protocol. See also
    :meth:`siotls.connection.TLSConnection.data_to_read`.
    """

    def __init__(self, data: bytes):  #:
        self.content_data = data

    @classmethod
    def parse(cls, stream, **kwargs):  # noqa: ARG003
        return cls(stream.read())

    def serialize(self):
        return self.content_data
