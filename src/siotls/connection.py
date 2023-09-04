import logging
import struct

from siotls.iana import ContentType
from siotls.serial import TooMuchData, SerialIO
from .contents import Content, alerts


logger = logging.getLogger(__name__)


class TLSConfiguration:
    def __init__(self, side):
        assert side in ('server', 'client')
        self.side = side


class TLSConnection:
    def __init__(self, config):
        self.config = config
        self.negociated_config = ...
        self._input_data = b''
        self._input_handshake = b''
        self._output_data = b''
        #self.state = (... if self.config.side == 'server' else ...)(self)
        self.encrypted = False

    def receive_data(self, data):
        if not data:
            return
        self._input_data += data

        contents = []
        for content_type, content_data in iter(self._read_next_content, None):
            stream = SerialIO(content_data)
            content = Content.get_parser(content_type).parse(stream)
            stream.assert_eof()
            contents.append(content)

        return contents

    def _read_next_record(self):
        if len(self._input_data) < 5:
            return

        content_type, _legacy_version, content_length = \
            struct.unpack('!BHH', self._input_data[:5])

        max_fragment_length = 2 ** 14 + (256 if self.encrypted else 0)
        if content_length > max_fragment_length:
            msg = (f'The record is longer ({content_length} bytes) than '
                   f'the allowed maximum ({max_fragment_length} bytes).')
            raise alerts.RecordOverFlow(msg)

        if len(self._input_data) - 5 < content_length:
            return

        fragment = self._input_data[5:content_length + 5]
        self._input_data = self._input_data[content_length + 5:]

        if not self.encrypted or content_type == ContentType.CHANGE_CIPHER_SPEC:
            return content_type, fragment

        innertext = self.decrypt(fragment)
        for i in range(len(innertext) -1, -1, -1):
            if innertext[i]:
                break
        else:
            return  # only padding

        content_type = innertext[i]
        fragment = innertext[:i-1]
        if content_type == ContentType.CHANGE_CIPHER_SPEC:
            msg = f"cannot receive encrypted {ContentType.CHANGE_CIPHER_SPEC}"
            raise alerts.UnexpectedMessage(msg)

        return content_type, fragment

    def _read_next_content(self):
        # handshakes can be fragmented over multiple following records,
        # other content types are not subject to fragmentation

        record = self._read_next_record()
        if not record:
            return

        content_type, fragment = record
        if not self._input_handshake:
            if content_type != ContentType.HANDSHAKE:
                return content_type, fragment
            else:
                self._input_handshake = fragment
        elif content_type != ContentType.HANDSHAKE:
            msg = (
                f"Expected {ContentType.HANDSHAKE} continuation "
                f"record but {content_type} found."
            )
            raise alerts.UnexpectedMessage(msg)
        else:
            self._input_handshake += fragment

        if len(self._input_handshake) < 4:
            return
        handshake_length = int.from_bytes(self._input_handshake[1:4], 'big')
        while len(self._input_handshake) - 4 < handshake_length:
            record = self._read_next_record()
            if not record:
                return
            content_type, fragment = record
            if content_type != ContentType.HANDSHAKE:
                msg = (f"Expected {ContentType.HANDSHAKE} continuation "
                       f"record but {content_type} found.")
                raise alerts.UnexpectedMessage(msg)
            self._input_handshake += fragment
        if len(self._input_handshake) - 4 > handshake_length:
            msg = (f"Expected {handshake_length + 4} bytes but "
                   f"{len(self._input_handshake)} read.")
            raise TooMuchData(msg)

        content_data = self._input_handshake
        self._input_handshake = b''
        return content_type, content_data
