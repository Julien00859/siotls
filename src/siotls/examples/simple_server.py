import logging
from socket import socket

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificates

from siotls import TLSConfiguration, TLSConnection
from siotls.utils import hexdump

logger = logging.getLogger(__name__)

def serve(host, port, certificate_chain_path, private_key_path):
    with open(certificate_chain_path, 'rb') as certificate_chain_file, \
         open(private_key_path, 'rb') as private_key_file:
        tls_config = TLSConfiguration(
            'server',
            private_key=load_pem_private_key(private_key_file.read(), None),
            certificate_chain=load_pem_x509_certificates(certificate_chain_file.read()),
        )

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
                handle_one(client, client_info, tls_config)
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


def handle_one(client, client_info, tls_config):
    conn = TLSConnection(tls_config)
    conn.initiate_connection()

    while True:
        input_data = client.recv(16384)
        if not input_data:
            break
        logger.info("%s bytes from %s:\n%s", len(input_data), client_info[1], hexdump(input_data))
        conn.receive_data(input_data)

        output_data = conn.data_to_send()
        if not output_data:
            break
        logger.info("%s bytes to %s:\n%s", len(output_data), client_info[1], hexdump(output_data))
        client.send(output_data)
