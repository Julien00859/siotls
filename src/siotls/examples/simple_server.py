import logging
import socket
from datetime import UTC, datetime
from http import HTTPStatus
from wsgiref.handlers import format_date_time

from siotls import USER_AGENT, TLSConfiguration, TLSConnection
from siotls.services.ocsp_over_http import OcspOverHttp
from siotls.utils import socket_pformat
from siotls.x509 import decode_pem_private_key, decode_pem_x509_certificates

logger = logging.getLogger(__name__)


def serve(host, port, certificate_chain_path, private_key_path, *, log_keys: bool):
    with (open(certificate_chain_path, 'rb') as certificate_chain_file,
          open(private_key_path, 'rb') as private_key_file):
        tls_config = TLSConfiguration(
            'server',
            private_key=decode_pem_private_key(private_key_file.read(), None),
            certificate_chain=decode_pem_x509_certificates(certificate_chain_file.read()),
            alpn=['http/1.1', 'http/1.0'],
            ocsp_service=OcspOverHttp(),  # ocsp stapling
            log_keys=log_keys,
        )

    server = socket.create_server((host, port), family=socket.AF_INET6)
    server_name = socket_pformat(server.getsockname(), default_port=443)
    logger.info("serving http on %s port %s (https://%s)", host, port, server_name)
    with server:
        while True:
            client, client_addr = server.accept()
            client_name = socket_pformat(client_addr)
            logger.info("connection with %s established", client_name)
            with client:
                conn = TLSConnection(tls_config)
                try:
                    with conn.wrap(client) as sclient:
                        logger.info("connection with %s secured", client_name)
                        http_serve_one(sclient, client_addr)
                except Exception:
                    logger.exception("connection with %s failed", client_name)
            logger.info("connection with %s closed", client_name)


def http_serve_one(sclient, client_addr):
    http_req = sclient.read()
    request_line = http_req.partition(b'\r\n')[0].decode(errors='replace')
    try:
        method, path, version = request_line.split(' ')
    except ValueError:
        code, body = 505, ""
    else:
        code, body = (
                 (405, "") if method != 'GET'
            else (404, "") if path != '/'
            else (200, "Hello from siotls\n")
        )
    now = datetime.now().astimezone()
    http_res = make_http11_response(code, body, now=now)
    sclient.write(http_res)
    logger.info(
        '%s - - [%s] "%s" %d %s',
        client_addr[0],
        now.strftime('%d/%b/%Y:%H:%M:%S %z'),
        request_line,
        code,
        len(body),
    )


def make_http11_response(code: int, textbody: str, now: datetime | None = None):
    date = format_date_time((now or datetime.now(UTC)).timestamp())
    status = HTTPStatus(code)
    return (
        f"HTTP/1.1 {status.value} {status.phrase}\r\n"
        f"Date: {date}\r\n"
        f"Server: {USER_AGENT}\r\n"
        f"Connection: close\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(textbody)}\r\n"
        f"\r\n"
    ).encode() + textbody.encode()
