import collections.abc
import logging
import time
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from urllib.parse import urlsplit

import h11
import rfc6555 as happy_eyesball

from siotls import USER_AGENT
from siotls.utils import intbyte

from . import TLSServiceError

logger = logging.getLogger(__package__)


class CacheMixin:
    _cache: collections.abc.MutableMapping
    stale = timedelta(seconds=60)

    def __init__(self, *args, cache, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = cache

    def _cache_get(self, key, default=None):
        data, expire = self._cache.get(key, (None, None))
        if not data:
            return default
        now = datetime.now(UTC)
        if now > expire - self.stale:
            self._cache_del(key)
            return default
        return data

    def _cache_set(self, key, data, expire):
        self._cache[key] = (data, expire)

    def _cache_del(self, key):
        self._cache.pop(key)


class RequestMixin:
    # Arbitrary
    conn_timeout: float = 2.0
    """ Time available to establishm the connection (DNS + TCP handshake). """

    # Arbitrary
    sock_timeout: float = 1.0
    """ Time available per socket.recv and socket.send. """

    # Recommandation of CA/B Forum 2.1.2 - 4.10.2 "Service Availability"
    http_timeout: float = 10.0
    """ Time available to complete the HTTP exchange. """

    # Same size as the record layer in TLS, a bit cargo culting
    chunk_length: int = intbyte('16kiB')
    """ How many bytes shall be received at once. """

    request_content_type: bytes
    """ The value of the request Content-Type when posting data. """

    request_body_max_length: int
    """ The maximum length of the request body, as a sanity check. """

    response_content_type: bytes
    """ The Content-Type to expect in the http response. """

    # With no Content-Security-Policy header, responses head usually fit
    # under 1kiB. 4kiB is very tolerent, doesn't consume that much RAM,
    # and protects against forged Content-Length headers (CVE-2020-10735).
    response_head_max_length: int = intbyte(4096)
    """ The maximum length of the response head (status line + headers). """

    response_body_max_length: int
    """
    The maximum length of the response body, checked against both the
    Content-Length response header and the data received on the wire.
    """

    def _request(self, url, data=b'') -> bytes:  # noqa: C901, PLR0912, PLR0915
        """
        Perform a untrusted HTTP/1.1 GET (empty data) or POST (data
        present) on the given URL. Return the response body.

        It is NOT RECOMMENDED to use this tool as a general purpose http
        client. This tool SHOULD only be used to download documents that
        are digitaly signed. Users MUST verify the signature before
        using the document.
        """
        # This function looks long and complicated but really isn't that
        # much. It really is only about sending a single HTTP request
        # and getting the response. What makes it complicated are all
        # the safeguards we added due to the high profile of siotls.
        #
        # This function has a bunch of securities that other common http
        # libraries don't have or aren't so strict: wall-clock timeout,
        # strict http/1.1, head and body length limits, happy eyesball.
        #
        # The problem mostly is that you can DOS all http.client based
        # libraries (urllib, urllib3, requests) by sending forever a
        # single byte at a time at a very slow rate. There is no way to
        # set a global per-request (instead of per-connect/recv/send)
        # timeout, and it'll happily read up headers up to 6MiB before
        # you get a chance to get control back. Not a problem as most of
        # the time you rely on TLS (HTTPS) to make sure that the server
        # is genuine and will behave well. But it's a deal breaker for
        # us, as we are only ever gonna talk in raw HTTP.
        #
        # We could have split this huge function into many smaller ones,
        # but the complexity would essentially have remained the same,
        # just you would be scrolling up and down much more.
        #
        # Just bear with it and remember that you are only reading a
        # 200ish line long function. That http.client + urllib are much
        # longer. Because you did read http.client and urllib(3) before
        # using requests, right? right?!

        # Prefix for all errors, so we don't have to type it everytime
        err = f'POST {url} [{len(data)} bytes]' if data else f'GET {url}'

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
                [('Content-Type', self.request_content_type)] if data else []
            )
        )

        sock = None
        try:
            # Connect to the remote host and set the various timeouts
            alarm = time.monotonic() + self.http_timeout

            sock = happy_eyesball.create_connection(
                (urlobj.hostname, urlobj.port or 80),
                timeout=self.conn_timeout,
            )
            sock.settimeout(self.sock_timeout)

            def socksend(data):
                sock.sendall(data)
                if time.monotonic() > alarm:
                    raise TimeoutError  # noqa: TRY301

            def sockrecv(size=self.chunk_length):
                data = sock.recv(size)
                if time.monotonic() > alarm:
                    raise TimeoutError  # noqa: TRY301
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
                        if bytes_recv > self.response_head_max_length:
                            e =(f"{err}: bad response headers, expected "
                                f"at most {self.response_head_max_length}, "
                                f"but read {bytes_recv} so far")
                            raise TLSServiceError(e)
                        data = sockrecv(min(
                            self.chunk_length, self.response_head_max_length))
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
            if content_length > self.response_body_max_length:
                e =(f"{err}: bad response Content-Length, expected at most "
                    f"{self.response_max_length}, got {content_length}")
                raise TLSServiceError(e)

            content_type = http_res.headers.get(b'content-type')
            if content_type != self.response_content_type:
                e =(f"{err}: bad response Content-Type, expected "
                    f"{self.response_content_type}, got {content_type}")
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
            e = f"{err}: timeout"
            raise TLSServiceError(e) from exc

        else:
            return body

        finally:
            if sock is not None:
                sock.close()
