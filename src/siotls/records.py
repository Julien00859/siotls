import enum
import struct

class ContentType(enum.IntEnum):
    invalid = 0
    change_cipher_spec = 20
    alert = 21
    handshake = 22
    application_data = 23


class TLSPlaintext:
    """ What is on the wire before encryption is setup """

    # struct {
    #     ContentType type;                       // 1 byte
    #     ProtocolVersion legacy_record_version;  // 2 bytes
    #     uint16 length;
    #     opaque fragment[TLSPlaintext.length];
    # } TLSPlaintext;

    type: ContentType
    _legacy_record_version = 0x0303
    fragment: bytes

    def __init__(self, type_, fragment):
        self.type = type_
        self.fragment = fragment

    def serialize(self):
        head = struct.pack(
            '!BHH',
            self.type,
            self._legacy_record_version,
            len(self.fragment)
        )
        return head + self.fragment

    @classmethod
    def deserialize(cls, data):
        type_, lcv, length = struct.unpack('!BHH')
        fragment = data[5:length+5]
        assert length == len(fragment)
        assert not data[length+5:]

        tpt = cls(type_, fragment)
        tpt._legacy_record_version = lcv

        return tpt

class TLSInnerPlaintext:
    """ The decrypted TLSCiphertext.encrypted_record """
    # struct {
    #     opaque content[TLSPlaintext.length];
    #     ContentType type;
    #     uint8 zeros[length_of_padding];
    # } TLSInnerPlaintext;

    content: bytes
    type: ContentType
    zeros: bytes

    def __init__(self, content, type, zeros):
        self.content = content
        self.type = type
        self.zeros = zeros

    def encrypt(self):
        return TLSCiphertext(...)


class TLSCiphertext:
    """ What is on the wire once encryption is setup """
    # struct {
    #     ContentType opaque_type = application_data; /* 23 */
    #     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    #     uint16 length;
    #     opaque encrypted_record[TLSCiphertext.length];
    # } TLSCiphertext;

    _opaque_type = 23
    _legacy_record_version = 0x0303
    encrypted_record: bytes

    def __init__(self, encrypted_record):
        self.encrypted_record = encrypted_record

    def serialize(self):
        head = struct.pack(
            '!BHH',
            self._opaque_type,
            self._legacy_record_version,
            len(self.encrypted_record)
        )
        return head + self.encrypted_record

    @classmethod
    def deserialize(cls, data):
        ot, lrv, length = struct.unpack('!BHH', data)
        encrypted_record = data[5:length+5]
        assert length == len(encrypted_record)
        assert not data[length+5:]

        tct = cls(encrypted_record)
        tcp._opaque_type = ot
        tcp._legacy_record_version = lrv
        return tct

    def decrypt(self):
        return TLSInnerPlaintext(self.encrypted_record)
