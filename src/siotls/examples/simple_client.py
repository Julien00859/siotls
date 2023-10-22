import logging
from socket import socket
from siotls import TLSConfiguration, TLSConnection
from siotls.utils import hexdump


logger = logging.getLogger(__name__)

def connect(host, port):
    config = TLSConfiguration('client')
    conn = TLSConnection(config)
    conn.initiate_connection()

    client = socket()
    try:
        client.connect((host, port))
        logger.info("connected to %s port %s", host, port)

        while True:
            output_data = conn.data_to_send()
            if not output_data:
                break
            logger.info("send %s bytes:\n%s", len(output_data), hexdump(output_data))
            client.send(output_data)

            input_data = client.recv(16384)
            if not input_data:
                break
            logger.info("recv %s bytes:\n%s", len(input_data), hexdump(input_data))
            conn.receive_data(input_data)

        logger.info("connection to %s port %s ended", host, port)
    finally:
        client.close()
