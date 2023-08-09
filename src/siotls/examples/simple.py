import logging
from pprint import pp
from socket import socket
from siotls.connection import TLSConnection
from siotls.utils import hexdump

logger = logging.getLogger(__name__)

def handle_one(client, client_info):

    conn = TLSConnection(config=None)

    while message := client.recv(1024):
        logger.info("%s bytes from %s:\n%s", len(message), client_info[1], hexdump(message))
        logger.info(conn.receive_data(message))

def serve(port, tlscert, tlskey):
    server = socket()
    server.bind(('localhost', port))
    server.listen(1)
    logger.info("listening on %s", port)

    try:
        while True:
            client = None
            client, client_info = server.accept()
            logger.info("new connection from %s", client_info[1])
            handle_one(client, client_info)
            logger.info("end of connection with %s", client_info[1])
    except KeyboardInterrupt:
        logger.info("closing server")
    finally:
        if client:
            client.close()
        server.close()
