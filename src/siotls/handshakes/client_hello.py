import logging
import textwrap
from siotls.iana import CipherSuites, HandshakeType, TLSVersion
from siotls.serial import SerializableBody, SerialIO
from . import Handshake
from ..contents import alerts
from ..extensions import Extension

logger = logging.getLogger(__name__)


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
    cipher_suites: list
    legacy_compression_methods: bytes = b'\x00'  # "null" compression method
    extensions: list[Extension]

    def __init__(self, random_, cipher_suites, extensions):
        self.random = random_
        self.cipher_suites = cipher_suites
        self.extensions = extensions

    @classmethod
    def parse_body(cls, data):
        stream = SerialIO(data)

        legacy_version = stream.read_int(2)
        if legacy_version != TLSVersion.TLS_1_2:
            raise alerts.ProtocolVersion()
        legacy_version = TLSVersion(legacy_version)

        random_ = stream.read_exactly(32)
        legacy_session_id = stream.read_var(1)

        cipher_suites = []
        it = iter(stream.read_var(2))
        for pair in zip(it, it):
            cipher = (pair[0] << 8) + pair[1]
            try:
                cipher_suites.append(CipherSuites(cipher))
            except ValueError:
                cipher_suites.append(cipher)

        legacy_compression_methods = stream.read_var(1)
        if legacy_compression_methods != b'\x00':  # "null" compression method
            raise alerts.IllegalParameter()

        extensions = []
        list_length = stream.read_int(2)
        while list_length > 0:
            with stream.lookahead():
                stream.read_exactly(2, limit=list_length)  # extension_type
                extension_length = stream.read_int(2, limit=list_length - 2)
            item_data = stream.read_exactly(4 + extension_length, limit=list_length)
            extension = Extension.parse(item_data, handshake_type=cls.msg_type)
            logger.debug("Found extension %s", extension)
            extensions.append(extension)
            list_length -= 4 + extension_length
        if list_length < 0:
            raise RuntimeError(f"buffer overflow while parsing {data}")

        stream.assert_eof()

        self = cls(random_, cipher_suites, extensions)
        self.legacy_version = legacy_version
        self.legacy_session_id = legacy_session_id
        self.legacy_compression_methods = legacy_compression_methods
        return self

    def serialize_body(self):
        raise NotImplementedError("todo")
