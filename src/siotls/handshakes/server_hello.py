import textwrap
from siotls.iana import HandshakeType
from siotls.serial import SerializableBody
from . import Handshake

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
    ...
