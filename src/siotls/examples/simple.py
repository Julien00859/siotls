import logging
from socket import socket
from siotls.connection import TLSConfiguration, TLSConnection
from siotls.utils import hexdump


logger = logging.getLogger(__name__)

def serve(host, port, tlscert, tlskey):
    server = socket()
    server.bind((host, port))
    server.listen(1)
    logger.info("listening on %s port %s", host, port)

    try:
        while True:
            client = None
            client, client_info = server.accept()
            logger.info("new connection from %s", client_info[1])
            try:
                handle_one(client, client_info)
            except Exception:
                logger.exception("while parsing data from %s", client_info[1])
            logger.info("end of connection with %s", client_info[1])
            client.close()
    except KeyboardInterrupt:
        logger.info("closing server")
    finally:
        if client:
            client.close()
        server.close()


def handle_one(client, client_info):
    config = TLSConfiguration('server')
    conn = TLSConnection(config)
    conn.initiate_connection()

    while input_data := client.recv(16384):
        logger.info("%s bytes from %s:\n%s", len(input_data), client_info[1], hexdump(input_data))
        conn.receive_data(input_data)

        output_data = conn.data_to_send()
        logger.info("%s bytes to %s:\n%s", len(input_data), client_info[1], hexdump(output_data))
        client.send(output_data)
