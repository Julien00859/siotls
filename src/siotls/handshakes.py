import enum
import struct
from contextlib import suppress
from .iana import ContentType, HandshakeType
from .serializable import Serializable, ProtocolIO

handshakemap = {}


class Handshake(Serializable):
    # struct {
    #     HandshakeType msg_type;    /* handshake type */
    #     uint24 length;             /* remaining bytes in message */
    #     select (Handshake.msg_type) {
    #         case client_hello:          ClientHello;
    #         case server_hello:          ServerHello;
    #         case end_of_early_data:     EndOfEarlyData;
    #         case encrypted_extensions:  EncryptedExtensions;
    #         case certificate_request:   CertificateRequest;
    #         case certificate:           Certificate;
    #         case certificate_verify:    CertificateVerify;
    #         case finished:              Finished;
    #         case new_session_ticket:    NewSessionTicket;
    #         case key_update:            KeyUpdate;
    #     };
    # } Handshake;
    msg_type: HandshakeType

    def __init_subclass__(cls, *, **kwargs):
        super().__init_subclass__(**kwargs)
        handshakemap[cls.msg_type] = cls


class ClientHello(Handshake):
    msg_type = HandshakeType.CLIENT_HELLO

    # uint16 ProtocolVersion;
    # opaque Random[32];
    #
    # uint8 CipherSuite[2];    /* Cryptographic suite selector */
    #
    # struct {
    #     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    #     Random random;
    #     opaque legacy_session_id<0..32>;
    #     CipherSuite cipher_suites<2..2^16-2>;
    #     opaque legacy_compression_methods<1..2^8-1>;
    #     Extension extensions<8..2^16-1>;
    # } ClientHello;
    legacy_version = TLSVersion.TLS_1_2
    random: bytes
    legacy_session_id = b''
    cipher_suites: list
    legacy_compression_methods = b'\x00'  # "null" compression method
    extensions: list['siotls.extensions.Extension']
    ...

    def __init__(self, random_, cipher_suites, extensions):
        self.random = random_
        self.cipher_suites = cipher_suites
        self.extensions = extensions

    @classmethod
    def parse(cls, data):
        stream = ProtocolIO(data)

        legacy_version = stream.read_int(2)
        with suppress(ValueError):
            legacy_version = TLSVersion(legacy_version)

        random_ = stream.read_exactly(32)
        legacy_session_id = stream.read_var(1)

        cipher_suites = []
        it = iter(stream.read_var(2))
        for pair in zip(it, it):
            # geometrie variable, pas bien !
            try:
                cipher_suites.append(CipherSuites(pair))
            except ValueError:
                cipher_suites.append(pair)

        legacy_compression_methods = stream.read_var(1)
        if legacy_compression_methods != '\x00':  # "null" compression method
            raise alerts.IllegalParameter()

        extensions = []
        extensions_length = stream.read_int(2)
        while extensions_length:
            extension_type = stream.read_int(2)
            extension_data = stream.read_var(2)
            extensions_length -= 4 + len(extension_data)
            if extension_cls := extensionmap.get(extension_type):
                if msg_type not in extension_cls.handshake_types:
                    raise ...
                extension = extension_cls.parse(extension_data)
            else:
                extension = UnknownExtension(extension_type, extension_data)
            extensions.append(extension)

        if remaining_data := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining_data} bytes remain.")

        self = cls(random_, cipher_suites, extensions)
        self.legacy_version = legacy_version
        self.legacy_session_id = legacy_session_id
        self.legacy_compression_methods = legacy_compression_methods
        return self

    def serialize(self):
        ...



class ServerHello(Handshake):
    msg_type = HandshakeType.SERVER_HELLO

    # struct {
    #     ProtocolVersion legacy_version = 0x0303;    /* TLS v1.2 */
    #     Random random;
    #     opaque legacy_session_id_echo<0..32>;
    #     CipherSuite cipher_suite;
    #     uint8 legacy_compression_method = 0;
    #     Extension extensions<6..2^16-1>;
    # } ServerHello;
    ...


class EndOfEarlyData(Handshake):
    msg_type = HandshakeType.END_OF_EARLY_DATA
    ...


class EncryptedExtensions(Handshake):
    msg_type = HandshakeType.ENCRYPTED_EXTENSIONS
    ...


class CertificateRequest(Handshake):
    msg_type = HandshakeType.CERTIFICATE_REQUEST
    ...


class Certificate(Handshake):
    msg_type = HandshakeType.CERTIFICATE
    ...


class CertificateVerify(Handshake):
    msg_type = HandshakeType.CERTIFICATE_VERIFY
    ...


class Finished(Handshake):
    msg_type = HandshakeType.FINISHED
    ...


class NewSessionTicket(Handshake):
    msg_type = HandshakeType.NEW_SESSION_TICKET
    ...


class KeyUpdate(Handshake):
    msg_type = HandshakeType.KEY_UPDATE
    ...

