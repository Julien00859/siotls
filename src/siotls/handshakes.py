import enum
import struct


class HandshakeType(enum.IntEnum):
    client_hello: 1
    server_hello: 2
    new_session_ticket: 4
    end_of_early_data: 5
    encrypted_extensions: 8
    certificate: 11
    certificate_request: 13
    certificate_verify: 15
    finished: 20
    key_update: 24
    message_hash: 254


class _Handshake:
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


class ClientHello(_Handshake):
    msg_type = HandshakeType.client_hello
    ...


class ServerHello(_Handshake):
    msg_type = HandshakeType.server_hello
    ...


class EndOfEarlyData(_Handshake):
    msg_type = HandshakeType.end_of_early_data
    ...


class EncryptedExtensions(_Handshake):
    msg_type = HandshakeType.encrypted_extensions
    ...


class CertificateRequest(_Handshake):
    msg_type = HandshakeType.certificate_request
    ...


class Certificate(_Handshake):
    msg_type = HandshakeType.certificate
    ...


class CertificateVerify(_Handshake):
    msg_type = HandshakeType.certificate_verify
    ...


class Finished(_Handshake):
    msg_type = HandshakeType.finished
    ...


class NewSessionTicket(_Handshake):
    msg_type = HandshakeType.new_session_ticket
    ...


class KeyUpdate(_Handshake):
    msg_type = HandshakeType.key_update
    ...

