import dataclasses
import logging
import textwrap
from siotls.iana import (
    CipherSuites, HandshakeType, HandshakeType_, ExtensionType, TLSVersion
)
from siotls.serial import SerialIO, SerializableBody
from siotls.utils import try_cast
from .. import alerts
from . import Handshake
from .extensions import Extension

logger = logging.getLogger(__name__)


@dataclasses.dataclass(init=False)
class ServerHello(Handshake, SerializableBody):
    msg_type = HandshakeType.SERVER_HELLO

    _struct = textwrap.dedent("""
        uint16 ProtocolVersion;
        opaque Random[32];

        uint8 CipherSuite[2];    /* Cryptographic suite selector */

        struct {
            ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
            Random random;
            opaque legacy_session_id_echo<0..32>;
            CipherSuite cipher_suite;
            uint8 legacy_compression_method = 0;
            Extension extensions<6..2^16-1>;
        } ServerHello;
    """).strip('\n')
    legacy_version: int = TLSVersion.TLS_1_2
    random: bytes
    legacy_session_id_echo: bytes = b''
    cipher_suite: CipherSuites | int
    legacy_compression_methods: int = 0  # "null" compression method
    extensions: dict[ExtensionType | int, Extension]

    def __init__(self, random, cipher_suite, extensions: list[Extension]):
        self.legacy_version = type(self).legacy_version
        self.random = random
        self.legacy_session_id_echo = type(self).legacy_session_id_echo
        self.cipher_suite = cipher_suite
        self.legacy_compression_methods = type(self).legacy_compression_methods
        self.extensions = {ext.extension_type: ext for ext in extensions}

    @classmethod
    def parse_body(cls, stream):
        legacy_version = stream.read_int(2)
        if legacy_version != TLSVersion.TLS_1_2:
            raise alerts.ProtocolVersion()
        legacy_version = TLSVersion(legacy_version)

        random = stream.read_exactly(32)
        if random == HelloRetryRequest.random:
            cls = HelloRetryRequest

        legacy_session_id_echo = stream.read_var(1)

        cipher_suite = try_cast(CipherSuites, stream.read_int(2))

        legacy_compression_methods = stream.read_int(1)
        if legacy_compression_methods != 0:  # "null" compression method
            raise alerts.IllegalParameter()

        extensions = []
        list_stream = SerialIO(stream.read_var(2))
        while not list_stream.is_eof():
            extension = Extension.parse(list_stream, handshake_type=cls.msg_type)
            logger.debug("Found extension %s", extension)
            extensions.append(extension)

        self = cls(random, cipher_suite, extensions)
        self.legacy_session_id_echo = legacy_session_id_echo
        return self

    def serialize_body(self):
        extensions = b''.join((ext.serialize() for ext in self.extensions.values()))

        return b''.join([
            self.legacy_version.to_bytes(2, 'big'),
            self.random,
            len(self.legacy_session_id_echo).to_bytes(1, 'big'),
            self.legacy_session_id_echo,
            self.cipher_suite.to_bytes(2, 'big'),
            self.legacy_compression_methods.to_bytes(1, 'big'),
            len(extensions).to_bytes(2, 'big'),
            extensions,
        ])


class HelloRetryRequest(ServerHello):
    handshake_type = HandshakeType_.HELLO_RETRY_REQUEST

    # hashlib.sha256("HelloRetryRequest").digest()
    random = bytes.fromhex(
        "CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91"
        "C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C"
    )

    def __init__(self, cipher_suite, extensions):
        super().__init__(self.random, cipher_suite, extensions)
