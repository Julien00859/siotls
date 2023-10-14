import logging
from socket import socket
from siotls.connection import TLSConnection, TLSConfiguration
from siotls.utils import hexdump

logger = logging.getLogger(__name__)

def handle_one(client, client_info):

    config = TLSConfiguration(side='server')
    conn = TLSConnection(config)

    while message := client.recv(1024):
        logger.info("%s bytes from %s:\n%s", len(message), client_info[1], hexdump(message))
        logger.info(conn.receive_data(message))

def serve(host, port, tlscert, tlskey):
    server = socket()
    server.bind((host, port))
    server.listen(1)
    logger.info("listening on %s", port)

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
