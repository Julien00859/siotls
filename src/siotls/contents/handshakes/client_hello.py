import logging
import textwrap
from dataclasses import dataclass
from siotls.iana import CipherSuites, HandshakeType, ExtensionType, TLSVersion
from siotls.serial import SerializableBody, SerialIO
from siotls.utils import try_cast
from .extensions import Extension
from . import Handshake
from .. import alerts

logger = logging.getLogger(__name__)


@dataclass(init=False)
class ClientHello(Handshake, SerializableBody):
    msg_type = HandshakeType.CLIENT_HELLO
    _struct = textwrap.dedent("""
        uint16 ProtocolVersion;
        opaque Random[32];

        uint8 CipherSuite[2];    /* Cryptographic suite selector */

        struct {
            ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
            Random random;
            opaque legacy_session_id<0..32>;
            CipherSuite cipher_suites<2..2^16-2>;
            opaque legacy_compression_methods<1..2^8-1>;
            Extension extensions<8..2^16-1>;
        } ClientHello;
    """).strip('\n')

    legacy_version: int = TLSVersion.TLS_1_2
    random: bytes
    legacy_session_id: bytes = b''
    cipher_suites: list[CipherSuites | int]
    legacy_compression_methods: bytes = b'\x00'  # "null" compression method
    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, random, cipher_suites, extensions: list[Extension]):
        self.legacy_version = type(self).legacy_version
        self.random = random
        self.legacy_session_id = type(self).legacy_session_id
        self.cipher_suites = cipher_suites
        self.legacy_compression_methods = type(self).legacy_compression_methods
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def parse_body(cls, stream):
        legacy_version = stream.read_int(2)
        if legacy_version != TLSVersion.TLS_1_2:
            raise alerts.ProtocolVersion()
        legacy_version = TLSVersion(legacy_version)

        random = stream.read_exactly(32)
        legacy_session_id = stream.read_var(1)

        cipher_suites = [
            try_cast(CipherSuites, cipher_suite)
            for cipher_suite in stream.read_listint(2, 2)
        ]

        legacy_compression_methods = stream.read_var(1)
        if legacy_compression_methods != b'\x00':  # "null" compression method
            raise alerts.IllegalParameter()

        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(list_stream, handshake_type=cls.msg_type)
            logger.debug("Found extension %s", extension)
            extensions.append(extension)

        self = cls(random, cipher_suites, extensions)
        self.legacy_session_id = legacy_session_id
        return self

    def serialize_body(self):
        extensions = b''.join((ext.serialize() for ext in self.extensions.values()))

        return b''.join([
            self.legacy_version.to_bytes(2, 'big'),
            self.random,

            len(self.legacy_session_id).to_bytes(1, 'big'),
            self.legacy_session_id,

            (len(self.cipher_suites) * 2).to_bytes(2, 'big'),
            *[cs.to_bytes(2, 'big') for cs in self.cipher_suites],

            len(self.legacy_compression_methods).to_bytes(1, 'big'),
            self.legacy_compression_methods,

            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])
