import enum
import struct
from .iana import ContentType, TLSVersion
from .serializable import Serializable

from .handshakes import Handshake
from .alerts import Alert

recordmap {
    ContentType.HANDSHAKE: Handshake,
    ContentType.ALERT: Alert
}


class TLSPlaintext(Serializable):
    """ What is on the wire before encryption is setup """

    # struct {
    #     ContentType type;                       // 1 byte
    #     ProtocolVersion legacy_record_version;  // 2 bytes
    #     uint16 length;
    #     opaque fragment[TLSPlaintext.length];
    # } TLSPlaintext;

    type: ContentType
    _legacy_record_version = TLSVersion.TLS_1_2
    fragment: bytes

    def __init__(self, type_, fragment):
        self.type = type_
        self.fragment = fragment

    @classmethod
    def parse(cls, data):
        type_, lcv, length = struct.unpack('!BHH', data[:5])
        fragment = data[5:length+5]
        try:
            lcv = TLSVersion(lrv)
        except ValueError:
            pass
        self = cls(type_, fragment)
        self._legacy_record_version = lcv
        return self

    def decrypt(self):
        return TLSInnerPlaintext(self.fragment, self.type, zeros=b'')

    def serialize(self):
        head = struct.pack(
            '!BHH',
            self.type,
            self._legacy_record_version,
            len(self.fragment)
        )
        return head + self.fragment


class TLSCiphertext(Serializable):
    """ What is on the wire once encryption is setup """
    # struct {
    #     ContentType opaque_type = application_data; /* 23 */
    #     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    #     uint16 length;
    #     opaque encrypted_record[TLSCiphertext.length];
    # } TLSCiphertext;

    _opaque_type = ContentType.APPLICATION_DATA
    _legacy_record_version = TLSVersion.TLS_1_2
    encrypted_record: bytes

    def __init__(self, encrypted_record):
        self.encrypted_record = encrypted_record

    @classmethod
    def parse(cls, data):
        ot, lrv, length = struct.unpack('!BHH', data)
        encrypted_record = data[5:length+5]
        assert length == len(encrypted_record)
        assert not data[length+5:]

        self = cls(encrypted_record)
        try:
            self._opaque_type = ContentType(ot)
        except ValueError:
            self._opaque_type = ot
        try:
            self._legacy_record_version = TLSVersion(lrv)
        except ValueError:
            self._legacy_record_version = lrv
        return self

    def serialize(self):
        head = struct.pack(
            '!BHH',
            self._opaque_type,
            self._legacy_record_version,
            len(self.encrypted_record)
        )
        return head + self.encrypted_record

    def decrypt(self):
        data = ...(self.encrypted_record)
        for i in range(len(data) -1, -1, -1):
            if data[i]:
                break
        else:
            raise ...
        return TLSInnerPlaintext(content=data[:i-1], type_=data[i], zeros=data[i+1:])


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

    def __init__(self, content, type_, zeros):
        assert not any(zeros)
        self.content = content
        self.type = type_
        self.zeros = zeros

    def encrypt(self):
        encrypted_record = ...(self.content, self.type, self.zeros)
        return TLSCiphertext(encrypted_record)
