import logging
import socket
from datetime import datetime

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificates

from siotls import TLSConfiguration, TLSConnection, ocsp_over_http
from siotls.utils import make_http11_response

logger = logging.getLogger(__name__)


def serve(host, port, certificate_chain_path, private_key_path):
    with open(certificate_chain_path, 'rb') as certificate_chain_file, \
         open(private_key_path, 'rb') as private_key_file:
        tls_config = TLSConfiguration(
            'server',
            private_key=load_pem_private_key(private_key_file.read(), None),
            certificate_chain=load_pem_x509_certificates(certificate_chain_file.read()),
            alpn=['http/1.1', 'http/1.0'],
        )

    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    logger.info("listening on %s port %s", host, port)

    try:
        while True:
            client = None
            client, client_info = server.accept()
            client.settimeout(1)
            logger.info("connection with %s:%s established", client_info[0], client_info[1])
            try:
                handle_one(client, client_info, tls_config)
            except Exception:
                logger.exception("while handling %s", client_info)
            logger.info("connection with %s:%s closed", client_info[0], client_info[1])
            client.close()
    except KeyboardInterrupt:
        logger.info("closing server")
    finally:
        if client:
            client.close()
        server.close()


def handle_one(client, client_info, tls_config):
    conn = TLSConnection(tls_config, ocsp_service=ocsp_over_http)

    with conn.wrap(client) as sclient:
        logger.info("connection with %s:%s secured", client_info[0], client_info[1])
        http_req = sclient.read()
        try:
            request_line = http_req.decode().partition('\r\n')[0]
            method, path, version = request_line.split()
            if method != 'GET':
                code, body = 405, ""
            elif path != '/':
                code, body = 404, ""
            else:
                code, body = 200, "Hello from siotls\n"
        except ValueError:
            code, body = 400, ""

        now = datetime.now().astimezone()
        http_res = make_http11_response(code, body, now=now)
        sclient.write(http_res.encode())
        logger.info(
            '%s - - [%s] "%s" %d %s',
            client_info[0],
            now.strftime('%d/%b/%Y:%H:%M:%S %z'),
            request_line,
            code,
            len(body),
        )
