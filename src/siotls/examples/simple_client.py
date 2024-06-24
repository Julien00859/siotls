import logging
import socket

from siotls import TLSConfiguration, TLSConnection, ocsp_over_http
from siotls.trust_store import get_system_store
from siotls.utils import make_http11_request

logger = logging.getLogger(__name__)

def connect(host, port, check_certificate):
    options = {}
    if check_certificate:
        options['trust_store'] = get_system_store()
    config = TLSConfiguration('client', alpn=['http/1.1', 'http/1.0'], **options)

    with socket.create_connection((host, port), timeout=5) as sock:
        logger.info("connection with %s:%s established", host, port)

        conn = TLSConnection(config, server_hostname=host, ocsp_service=ocsp_over_http)
        with conn.wrap(sock) as ssock:
            logger.info("connection with %s:%s secured", host, port)

            http_req = make_http11_request(host, 'GET', '/', '')
            if logger.isEnabledFor(logging.DEBUG):
                print(http_req)  # noqa: T201
            ssock.write(http_req.encode())

            http_res = ssock.read().decode(errors='replace')
            if logger.isEnabledFor(logging.INFO):
                print(http_res)  # noqa: T201

    logger.info("connection with %s:%s ended", host, port)
