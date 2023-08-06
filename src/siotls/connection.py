class TLSConfiguration:
    def __init__(self, side):
        assert side in ('server', 'client')
        self.side = side


class TLSConnection:
    def __init__(self, config):
        self.config = config
        self.negociated_config = ...
        self.input_data = b''
        self.output_data = b''

        self.state = (... if self.config.side == 'server' else ...)(self)

    def receive_data(self, data):
        events = []

        self.input_data += data
        try:
            ...
        except MissingData:
            pass

        return events

    def data_to_send(self):
        output_data = self.output_data
        self.output_data = b''
        return output_data
