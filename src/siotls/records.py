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
    #     uint16 length;                          // 2 bytes
    #     opaque fragment[TLSPlaintext.length];
    # } TLSPlaintext;

    type: ContentType
    fragment: bytes

    def __init__(self, type_, fragment):
        self.type = type_
        self.legacy_record_version = 0x0303
        self.fragment = fragment

    @classmethod
    def deserialize(cls, data):
        if len(data) < 5:
            raise ValueError(f"Cannot read a header of 5 bytes from a data of {len(data)} bytes")

        type_, lcv, length = struct.unpack('!BHH')
        if len(data) - 5 < length:
            raise ValueError(f"Cannot read a body of {length} bytes from a data of {len(data) - 5} bytes")

        fragment = data[5:length+5]

        tpt = cls(type_, fragment)
        tpt.legacy_record_version = lcv

        return data[length+5:]
