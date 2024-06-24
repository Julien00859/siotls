

class WrappedSocket:
    def __init__(self, conn, sock):
        self.conn = conn
        self.sock = sock

    def __enter__(self):
        self.do_handhskake()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def do_handhskake(self):
        self.conn.initiate_connection()
        if self.conn.config.side == 'client':
            self.sock.send(self.conn.data_to_send())
        while not self.conn.is_post_handshake():
            if input_data := self.sock.recv(self.conn.max_fragment_length):
                try:
                    self.conn.receive_data(input_data)
                finally:
                    if output_data := self.conn.data_to_send():
                        self.sock.send(output_data)
            else:
                self.conn.close_receiving_end()  # it goes post handshake

    def read(self):
        application_data = self.conn.data_to_read()
        while self.conn.is_connected() and not application_data:
            if input_data := self.sock.recv(self.conn.max_fragment_length):
                try:
                    self.conn.receive_data(input_data)
                finally:
                    if output_data := self.conn.data_to_send():
                        self.sock.send(output_data)
                application_data += self.conn.data_to_read()
            else:
                self.conn.close_receiving_end()
        return application_data

    def write(self, data):
        self.conn.send_data(data)
        self.sock.send(self.conn.data_to_send())

    def close(self):
        self.conn.close_sending_end()
        if close_notify := self.conn.data_to_send():
            self.sock.send(close_notify)
