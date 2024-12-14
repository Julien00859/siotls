import logging
import socket

from siotls import USER_AGENT, TLSConfiguration, TLSConnection
from siotls.services.crl_over_http import CrlOverHttp
from siotls.services.ocsp_over_http import OcspOverHttp
from siotls.trust_store import get_system_store

logger = logging.getLogger(__name__)

def connect(host, port, *, check_certificate: bool, log_keys: bool):
    options = {}
    if check_certificate:
        options['trust_store'] = get_system_store()
        options['crl_service'] = CrlOverHttp()
        options['ocsp_service'] = OcspOverHttp()
    config = TLSConfiguration(
        'client',
        alpn=['http/1.1', 'http/1.0'],
        log_keys=log_keys,
        **options,
    )

    with socket.create_connection((host, port), timeout=5) as sock:
        logger.info("connection with %s established", host)
        conn = TLSConnection(config, server_hostname=host)
        with conn.wrap(sock) as ssock:
            logger.info("connection with %s secured", host)
            http_connect_one(host, ssock)
    logger.info("connection with %s closed", host)


def http_connect_one(host, ssock):
    http_req = make_http11_request(host, 'GET', '/', '')
    if logger.isEnabledFor(logging.DEBUG):
        print(http_req.decode('latin-1'))  # noqa: T201
    ssock.write(http_req)

    http_res = ssock.read().decode('latin-1')
    if logger.isEnabledFor(logging.INFO):
        print(http_res)  # noqa: T201


def make_http11_request(host: str, method: str, path: str, textbody: str):
    return (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(textbody)}\r\n"
        f"User-Agent: {USER_AGENT}\r\n"
        "\r\n"
    ).encode() + textbody.encode()
