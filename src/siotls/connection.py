import logging

from .serial import SerialIO, MissingData
from .iana import ContentType
from . import alerts
from .contents import content_registry


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
        self._output_data = b''
        #self.state = (... if self.config.side == 'server' else ...)(self)
        self.encrypted = False

    def receive_data(self, data):
        if not data:
            return
        self._input_data += data
        if len(self._input_data) < 5:
            return

        stream = SerialIO(self._input_data)
        contents = self._process_stream(stream)
        self._input_data = self._input_data[stream.tell()]
        return self._process_contents(contents)

    def _process_stream(self, stream):
        contents = []
        while record := self._get_next_record(stream):
            content_type, fragment = record
            if content_type != ContentType.HANDSHAKE:
                data = fragment
            elif len(fragment) < 4:
                raise alerts.DecodeError()
            else:
                handshake_length = int.from_bytes(fragment[1:3], 'big')
                data = bytearray(fragment)
                while len(data) < handshake_length + 6:
                    record = self._get_next_record(stream)
                    if not record:
                        raise MissingData()

                    fragment_type, fragment = record
                    if fragment_type != ContentType.HANDSHAKE:
                        raise alerts.UnexpectedMessage()
                    if not fragment:
                        logger.warning("Empty continuation handshake, close")
                        raise alerts.UnexpectedMessage()
                    data += fragment

            contents.append(content_registry[content_type].parse(data))

        return contents


    def _get_next_record(self, stream):
        pos = stream.tell()
        try:
            content_type = stream.read_int(1)
            legacy_version = stream.read_int(2)
            content_length = stream.read_int(2)
            if content_length > 2 ** 14:  # TODO: MaxFragmentLength
                raise alerts.RecordOverflow()
            fragment = stream.read_exactly(content_length)
        except MissingData:
            stream.seek(pos)
            return

        if not self.encrypted:
            return content_type, fragment

        innertext = self.decrypt(fragment)
        for i in range(len(innertext) -1, -1, -1):
            if innertext[i]:
                break
        else:
            raise ...
        return innertext[i], innertext[:i-1]

    def _process_contents(contents):
        return contents
        #return []
