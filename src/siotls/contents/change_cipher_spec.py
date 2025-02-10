import dataclasses
import textwrap

from siotls.iana import ContentType
from siotls.serial import Serializable

from . import Content, alerts


@dataclasses.dataclass(init=False)
class ChangeCipherSpec(Content, Serializable):
    """
    A content that has no meaning in TLS 1.3 but that is still
    transmitted because of `protocol ossification`_, see
    :rfc:`8446#appendix-D.4` (TLS 1.3 - Middlebox Compatibility Mode).

    .. _protocol ossification: https://en.wikipedia.org/wiki/Protocol_ossification
    """

    content_type = ContentType.CHANGE_CIPHER_SPEC
    can_fragment = False

    _struct = textwrap.dedent("""
        opaque data = 0x01;
    """).strip('\n')

    def __init__(self):
        pass

    @classmethod
    def parse(cls, stream, **kwargs):  # noqa: ARG003
        data = stream.read_exactly(1)
        if data != b'\x01':
            e = f"invalid {ContentType.CHANGE_CIPHER_SPEC} value: {data}"
            raise alerts.UnexpectedMessage(e)
        return cls()

    def serialize(self):
        return b'\x01'
