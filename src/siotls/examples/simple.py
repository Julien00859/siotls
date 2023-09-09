import logging
from pprint import pp
from socket import socket
import secrets
from siotls.connection import TLSConnection
from siotls.contents import alerts
from siotls.handshakes import ServerHello
from siotls.utils import hexdump
from siotls.iana import (
    HandshakeType as HT,
    ExtensionType as ET,
    TLSVersion,
    CipherSuites,
)

logger = logging.getLogger(__name__)

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


def handle_one(client, client_info):
    conn = TLSConnection(config=None)
    message = client.recv(16384)
    logger.info("%s bytes from %s:\n%s", len(message), client_info[1], hexdump(message))

    handshakes = conn.receive_data(message)
    if not handshakes or handshakes[0].handshake_type is not HT.CLIENT_HELLO:
        raise alerts.UnexpectedMessage()

    client_hello = handshakes.pop(0)
    ext_sv = client_hello.get_extension(ET.SUPPORTED_VERSIONS, None)
    if not ext_sv:
        raise NotImplementedError("todo")  # bad version
    if TLSVersion.TLS_1_3 not in ext_sv.versions:
        raise NotImplementedError("todo")  # bad version

    if CipherSuites.TLS_CHACHA20_POLY1305_SHA256 not in client_hello.cipher_suites:
        raise NotImplementedError("todo")

    server_hello = ServerHello(
        secrets.token_bytes(32),
        CipherSuites.TLS_CHACHA20_POLY1305_SHA256,  # cipher
        [],  # extensions
    )
    server_hello.legacy_session_id_echo = client_hello.legacy_session_id
