import dataclasses
import logging
import textwrap

from siotls.iana import ExtensionType, HandshakeType
from siotls.serial import SerialIO, SerializableBody

from . import Handshake
from .extensions import Extension

logger = logging.getLogger(__name__)


@dataclasses.dataclass(init=False)
class EncryptedExtensions(Handshake, SerializableBody):
    msg_type = HandshakeType.ENCRYPTED_EXTENSIONS

    _struct = textwrap.dedent("""
        struct {
            Extension extensions<0..2^16-1>;
        } EncryptedExtensions;
    """).strip('\n')

    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, extensions: list[Extension]):
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def parse_body(cls, stream):
        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(list_stream, handshake_type=cls.msg_type)
            extensions.append(extension)

        return cls(extensions)

    def serialize_body(self):
        extensions = b''.join(ext.serialize() for ext in self.extensions.values())
        return b''.join([
            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])
