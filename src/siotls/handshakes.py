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
    legacy_version = 0x0303
    random: bytes
    legacy_session_id: bytes
    cipher_suites: list
    legacy_compression_methods: bytes
    extensions: list['siotls.extensions.Extension']
    ...

    @classmethod
    def parse(cls, data):
        stream = ProtocolIO(data)

        msg_type = HandshakeType(stream.read_int(1))
        length = stream.read_int(3)
        if len(data) < length:
            raise ...  # missing data, bail
        if len(data) > length:
            raise ...  # protocol error

        legacy_version = stream.read_int(2)
        with suppress(ValueError):
            legacy_version = TLSVersion(legacy_version)

        random_ = stream.read_exactly(32)
        session_id = stream.read_var(1)
        cipher_suites = list(map(CipherSuites, zip(it:=iter(stream.read_var(2)), it)))
        compression_methods = stream.read_var(1)
        extensions = []

        extensions_length = stream.read_int(2)
        while extensions_length:
            extension_type = stream.read_int(2)
            Extension[extension_type]

            try:
                extension.type = ExtensionType(extension.type)
            except ValueError:
                pass
            length = int.from_bytes(read(2), 'big')
            extension.data = stream.read(length)
            handshake.extensions.append(vars(extension))
            extensions_length -= length + 4

        pp(vars(record))
        pp(vars(handshake))



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

