import enum
from .iana import ContentType, TLSVersion
from .serial import Serializable, SerialIO


class Record(Serializable):
    content_type: ContentType
    legacy_record_version: TLSVersion
    fragment: bytes

    @classmethod
    def parse(cls, data):
        stream = SerialIO(data)

        raw_content_type = stream.read_int(1)
        try:
            content_type = ContentType(content_type)
        except ValueError:
            ...

        legacy_record_version = stream.read_int(2)
        with suppress(ValueError):
            legacy_record_version = TLSVersion(legacy_record_version)

        length = stream.read_int(2)
        if length > 2 ** 14:  # TODO: MaxFragmentLength
            raise alerts.RecordOverflow()

        raw_content = stream.read_exactly(length)

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        return cls(content_type, legacy_record_version, raw_content)



class TLSPlaintext(Serializable):
    """ What is on the wire before encryption is setup """

    # struct {
    #     ContentType type;                       // 1 byte
    #     ProtocolVersion legacy_record_version;  // 2 bytes
    #     uint16 length;
    #     opaque fragment[TLSPlaintext.length];
    # } TLSPlaintext;

    content_type: ContentType
    legacy_record_version = TLSVersion.TLS_1_2
    raw_content: bytes

    def __init__(self, content_type, raw_content):
        self.content_type = content_type
        self.raw_content = raw_content

    def serialize(self):
        return b''.join(
            self.content_type.to_bytes(1, 'big'),
            self.legacy_record_version.to_bytes(2, 'big'),
            len(self.raw_content).to_bytes(2, 'big'),
            self.raw_content,
        )


class TLSCiphertext(TLSPlaintext):
    """ What is on the wire once encryption is setup """
    # struct {
    #     ContentType opaque_type = application_data; /* 23 */
    #     ProtocolVersion legacy_record_version = 0x0303; /* TLS v1.2 */
    #     uint16 length;
    #     opaque encrypted_record[TLSCiphertext.length];
    # } TLSCiphertext;

    content_type = ContentType.APPLICATION_DATA

    def __init__(self, raw_content):
        self.raw_content = raw_content

    @classmethod
    def parse(cls, data):
        payload = bytearray()
        stream = SerialIO(data)
        stream.read_exactly(3)  # skip opaque_type and legacy_record_version

        length = stream.read_int(2)
        if length > 2 ** 14:  # TODO: MaxFragmentLength
            raise alerts.RecordOverflow()
        encrypted_record = stream.read_exactly(length)

        if remaining := len(data) - stream.tell():
            raise ValueError(f"Expected end of stream but {remaining} bytes remain.")

        return cls(content_type, content, zeros)

    def decrypt(self, encrypted_record):
        ...
        for i in range(len(innertext) -1, -1, -1):
            if innertext[i]:
                break
        else:
            raise ...
        payload += innertext[:i-1]
        content_type = ContentType(innertext[i])
        zeros = innertext[i+1:]
        return content_type, content, zeros

    def serialize(self):
        payload = self.content.serialize()
        if len(payload) > 2**14:  # TODO: MaxFragmentLength
            ...  # TODO: fragment

        innertext = b''.join(
            payload,
            self.content_type.to_bytes(1, 'big'),
            self.zeros,
        )
        encrypted_record = self.encrypt(innertext)

        return b''.join(
            ContentType.APPLICATION_DATA.to_bytes(1, 'big'),
            TLSVersion.TLS_1_2.to_bytes(2, 'big')
            len(innertext).to_bytes(2, 'big'),
            innertext,
        )
