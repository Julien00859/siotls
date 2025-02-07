# noqa: INP001

import logging
import time
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from urllib.parse import urlsplit

import h11
from pyasn1_modules.rfc5280 import Certificate

from siotls import USER_AGENT
from siotls.services import TLSService
from siotls.services.ocsp import load_verify_ocsp
from siotls.services.filestore import FileStore
from siotls.services.sievecache import SieveCache
from siotls.utils import intbyte

from . import TLSServiceError, TLSServiceErrorGroup, happy_eyeballs

logger = logging.getLogger(__package__)


class WallClockTimeoutError(TimeoutError):
    pass


class CacheHelper:
    def __init__(self, cache, stale=timedelta(seconds=60)):
        self._cache = cache
        self.state = stale

    def get(self, key, default=None):
        data, expire = self._cache.get(key, (None, None))
        if not data:
            return default
        now = datetime.now(UTC)
        if now > expire - self.stale:
            self.rem(key)
            return default
        return data

    def set(self, key, data, expire):
        self._cache[key] = (data, expire)

    def rem(self, key):
        self._cache.pop(key)



class SimpleService(TLSService):
    def __init__(self):
        self._ocsp_cache = CacheHelper(SieveCache())
        self._file_cache = CacheHelper(FileStore())

    def request_ocsp(self, url: str, ocsp_req_data: bytes, signer_cert: Certificate):
        if ocsp_res_data := self._ocsp_cache.get(ocsp_req_data):
            return ocsp_res_data

        ocsp_res_data = saferequest(
            url,
            ocsp_req_data,
            request_content_type = b'application/ocsp-request',
            request_body_max_length = intbyte(1024),
            response_content_type = b'application/ocsp-response',
            response_body_max_length = intbyte('32kiB')  # longest ocsp res I have is 12kiB
        )
        ocsp_basic_res = load_verify_ocsp(ocsp_req_data, ocsp_res_data, signer_cert)

        next_update = ocsp_basic_res['tbsResponseData']['responses'][0]['nextUpdate']
        if next_update:
            self._ocsp_cache.set(ocsp_req_data, ocsp_res_data, next_update)

        return ocsp_res_data, ocsp_basic_res

    def download_crl(self, *a, **kw):
        raise NotImplementedError("todo")  # noqa: EM101
        saferequest(
            ...,
            response_content_type=b'application/pkix-crl',
            response_body_max_length=intbyte('16MiB')  # longest crl I have (DigitCert) is 7MiB,
        )

    def download_cert(self, urls):
        if not urls:
            e = "missing url"
            raise ValueError(e)

        for url in urls:
            if cert := self._cache_get(url):
                # TODO: verify that is hasn't been revoked since then
                return cert

        excs = []
        for url in urls:
            try:
                cert_res = saferequest(
                    url,
                    response_content_type=b'application/pkix-cert',
                    response_max_length=intbyte('64kiB'),  # longest cert chain I have is 16kiB
                )
                break
            except TLSServiceError as exc:
                excs.append(exc)
                continue
        else:
            e = "all URLs failed"
            raise TLSServiceErrorGroup(e, excs)

        try:
            cert = load_der_certificate(cert_res)
        except ValueError as exc:
            e = "error while loading certificate"
            raise TLSServiceError(e) from exc

        return cert_res, cert


def saferequest(  # noqa: C901, PLR0912, PLR0913, PLR0915
    url: str,
    data: bytes = b'',
    *,

    # Arbitrary
    conn_timeout: float = 2.0,

    # Arbitrary
    sock_timeout: float = 1.0,

    # Recommandation of CA/B Forum 2.1.2 - 4.10.2 "Service Availability"
    http_timeout: float = 10.0,

    # Same size as the record layer in TLS, a bit cargo culting
    chunk_length: int = intbyte('16kiB'),

    # Required with data
    request_content_type: bytes | None = None,

    # Required with data
    request_body_max_length: int | None = None,

    # Required
    response_content_type: bytes,

    # With no Content-Security-Policy header, responses head usually fit
    # under 1kiB. 4kiB is very tolerent, doesn't consume that much RAM,
    # and protects against forged Content-Length headers (CVE-2020-10735).
    response_head_max_length: int = intbyte(4096),

    # Required
    response_body_max_length: int,
) -> bytes:
    """
    Perform a untrusted HTTP/1.1 GET (empty data) or POST (data present)
    on the given URL. Return the response body.

    It is NOT RECOMMENDED to use this tool as a general purpose http
    client. This tool SHOULD only be used to download documents that
    are digitaly signed. Users MUST verify the signature before
    using the document.

    :param url: The remote location where to connect
    :param data: The data to send with a POST request.
    :param conn_timeout: Time available to establishm the connection
        (DNS + TCP handshake).
    :param sock_timeout: Time available per socket.recv and socket.send.
    :param http_timeout: Time available to complete the HTTP exchange,
        with a precision down to ``sock_timeout``.
    :param chunk_length: How many bytes shall be received at once.
    :param request_content_type: The value of the request Content-Type
        when posting data.
    :param request_body_max_length: The maximum length of the request
        body, as a sanity check.
    :param response_content_type: The Content-Type to expect in the http
        response.
    :param response_head_max_length: The maximum length of the response
        head (status line + headers).
    :param response_body_max_length: The maximum length of the response
        body, checked against both Content-Length response header and
        the data received on the wire.
    """
    # This function looks long and complicated but isn't that much.
    #
    # It really is only about sending a single HTTP request and getting
    # the response. What makes it complicated are all the safeguards we
    # added due to the high profile of siotls, safeguards that typically
    # are not found in other (synchronous) http libraries include. They
    # include: wall-clock timeout, strict http/1.1, head and body length
    # limits, happy eyesball.
    #
    # We could have split this huge function into many smaller ones, but
    # the complexity would essentially have remained the same, just you
    # would be scrolling up and down much more.
    #
    # Bear with it and remember that you are only reading a 200ish line
    # long function. That http.client + urllib are much longer. Because
    # you did read http.client and urllib(3) before using the infamous
    # requests library, right? right?!

    # Prefix for all errors, so we don't have to type it everytime
    err = f'POST {url} [{len(data)} bytes]' if data else f'GET {url}'

    if len(data) > request_body_max_length:
        e =(f"{err}: bad request body, forbidden to send more than "
            f"{request_body_max_length} bytes")
        raise ValueError(e)

    # Prepare the request
    urlobj = urlsplit(url)
    if urlobj.scheme != 'http':
        e = "url scheme must be http"
        raise ValueError(e)
    if not urlobj.netloc:
        e = "url authority cannot be empty"
        raise ValueError(e)
    http_req = h11.Request(
        method=b'POST' if data else b'GET',
        target=f'{urlobj.path}?{urlobj.query}',
        headers=[
            ('Host', urlobj.netloc),
            ('User-Agent', USER_AGENT),
            ('Content-Length', str(len(data))),
        ] + (
            [('Content-Type', request_content_type)] if data else []
        )
    )

    sock = None
    try:
        # Connect to the remote host and set the various timeouts
        alarm = time.perf_counter() + http_timeout

        sock = happy_eyeballs.create_connection(
            (urlobj.hostname, urlobj.port or 80),
            timeout=conn_timeout,
        )
        sock.settimeout(sock_timeout)

        def socksend(data):
            sock.sendall(data)
            if time.perf_counter() > alarm:
                raise WallClockTimeoutError

        def sockrecv(size=chunk_length):
            data = sock.recv(size)
            if time.perf_counter() > alarm:
                raise WallClockTimeoutError
            return data

        # Send the HTTP request (request line + head + body)
        conn = h11.Connection(h11.CLIENT)
        socksend(conn.send(http_req))
        if data is not None:
            socksend(conn.send(h11.Data(data)))
        socksend(conn.send(h11.EndOfMessage()))

        # Read the HTTP response head (status line + head)
        bytes_recv = intbyte(0)
        while True:
            event = conn.next_event()
            match event:
                case h11.NEED_DATA:
                    if bytes_recv > response_head_max_length:
                        e =(f"{err}: bad response headers, expected at "
                            f"most {response_head_max_length}, but "
                            f"read {bytes_recv} so far")
                        raise TLSServiceError(e)
                    data = sockrecv(min(
                        chunk_length, response_head_max_length))
                    bytes_recv += len(data)
                    conn.receive_data(data)
                case h11.Response():
                    break
                case h11.ConnectionClosed():
                    e = f"{err}: connection closed by peer"
                    raise TLSServiceError(e)
                case _:
                    e = f"{err}: unexpected event: {event}"
                    raise TLSServiceError(e)

        # Make sure we got a 200 with a good CT-Length and CT-Type
        http_res = event
        if http_res.status_code != HTTPStatus.OK:
            e =(f"{err}: bad response status, expected 200, got "
                f"{HTTPStatus(http_res.status_code)!r}")
            raise TLSServiceError(e)

        content_length = http_res.headers.get(b'content-length')
        if content_length is None:
            e = f"{err}: missing mandatory response Content-Length"
            raise TLSServiceError(e)

        content_length = int(content_length)  # h11 validated it
        if content_length > response_body_max_length:
            e =(f"{err}: bad response Content-Length, expected at most "
                f"{response_body_max_length}, got {content_length}")
            raise TLSServiceError(e)

        content_type = http_res.headers.get(b'content-type')
        if content_type != response_content_type:
            e =(f"{err}: bad response Content-Type, expected "
                f"{response_content_type}, got {content_type}")
            raise TLSServiceError(e)

        body = bytearray()
        while True:
            event = conn.next_event()
            match event:
                case h11.NEED_DATA:
                    # h11 verifies the length of the body
                    conn.receive_data(sockrecv())
                case h11.Data():
                    body += event.data
                case h11.EndOfMessage():
                    break
                case _:
                    e = f"{err}: unexpected event: {event}"
                    raise TLSServiceError(e)

    except OSError as exc:
        e = f"{err}: connection failure"
        raise TLSServiceError(e) from exc

    except h11.RemoteProtocolError as exc:
        e = f"{err}: bad http response"
        raise TLSServiceError(e) from exc

    except TimeoutError as exc:
        kind = ( "connection (conn)" if not sock
            else "wall-clock (http)" if isinstance(exc, WallClockTimeoutError)
            else "tcp read/write (sock)")
        e = f"{err}: {kind} timeout"
        raise TLSServiceError(e) from exc

    else:
        return body

    finally:
        if sock is not None:
            sock.close()
