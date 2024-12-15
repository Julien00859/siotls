import logging
import socket

from siotls import USER_AGENT, TLSConfiguration, TLSConnection
from siotls.services.crl_over_http import CrlOverHttp
from siotls.services.ocsp_over_http import OcspOverHttp
from siotls.trust_store import get_system_store
from siotls.utils import socket_pformat

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
        server_name = socket_pformat((host, port))
        logger.info("connection with %s established", server_name)
        conn = TLSConnection(config, server_hostname=host)
        with conn.wrap(sock) as ssock:
            logger.info("connection with %s secured", server_name)
            http_connect_one(host, ssock)
    logger.info("connection with %s closed", server_name)


def http_connect_one(host, ssock):
    http_req = make_http11_request(host, 'GET', '/', '')
    logger.debug("sending payload:\n%s", http_req.decode())
    ssock.write(http_req)

    http_res = ssock.read()
    headers, _, body = http_res.partition(b'\r\n\r\n')
    logger.debug("received headers:\n%s", headers.decode(errors='replace'))
    print(body.decode(errors='replace'))  # noqa: T201


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
