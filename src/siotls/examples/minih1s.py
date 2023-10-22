#!/usr/bin/env python3
"""
Mini HTTP/1.1 server over TLS with openssl, used to test the siotls
client against another TLS implementation.
"""
import argparse
import importlib.resources
import logging
import socket
import ssl
import textwrap
import time
import sys
from email.utils import formatdate
from pathlib import Path

import sslkeylog


__file_path__ = Path(__file__)  # eventually standard??
logger = logging.getLogger(__file_path__.stem)
SERVER = "{} Python/{} OpenSSL/{}".format(
    __file_path__.stem,
    '.'.join(map(str, sys.version_info[:3])),
    '.'.join(map(str, ssl.OPENSSL_VERSION_INFO[:3])),
)


def main():
    logging.basicConfig(level='INFO')
    parser = argparse.ArgumentParser(prog=__file_path__.stem)
    parser.add_argument('--host', action='store', default='localhost',
        help="IP address on which the server will listen")
    parser.add_argument('--port', action='store', type=int, default=8446,
        help="TCP port number on which the server will listen")
    parser.add_argument('--tlscert', '--sslcert', action='store', type=Path,
        default=importlib.resources.path('siotls.data', 'self-signed-cert.pem'),
        help="Path to the SSL/TLS certificate file", metavar="PATH")
    parser.add_argument('--tlskey', '--sslkey', action='store', type=Path,
        default=importlib.resources.path('siotls.data', 'self-signed-key.pem'),
        help="Path to the SSL/TLS private key file", metavar="PATH")
    parser.add_argument('--tlskeylogfile', '--sslkeylogfile', action='store',
        default=str(Path().home() / '.sslkeylogfile'),
        help="Where to log the secrets for tools like wireshark", metavar="PATH")
    options = parser.parse_args()

    if options.tlskeylogfile:
        sslkeylog.set_keylog(options.tlskeylogfile)

    serve(options.host, options.port, options.tlscert, options.tlskey)


def serve(host, port, tlscert, tlskey):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.set_alpn_protocols(['http/1.1'])
    context.load_cert_chain(tlscert, tlskey)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((host, port))
        sock.listen()
        logger.info("listening on %s port %s", host, port)
        with context.wrap_socket(sock, server_side=True) as server:
            try:
                while True:
                    client = None
                    try:
                        client, client_info = server.accept()
                    except Exception:
                        logger.exception("while accepting incomming connection")
                        continue
                    logger.info("new connection from %s", client_info[1])
                    try:
                        client.recv(16384)
                        client.send(textwrap.dedent(f"""\
                            HTTP/1.1 204 No Content
                            Date: {formatdate(time.time(), usegmt=True)}
                            Server: {SERVER}
                            Connection: close

                        """).encode())
                    except Exception:
                        logger.exception("while serving %s", client_info[1])
                    logger.info("end of connection with %s", client_info[1])
                    client.close()
            except KeyboardInterrupt:
                logger.info("closing server")
            finally:
                if client:
                    client.close()
                server.close()
                sock.close()


if __name__ == '__main__':
    main()
