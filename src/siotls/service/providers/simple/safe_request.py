import time
from http import HTTPStatus
from urllib.parse import urlsplit

import h11

from siotls import TLSError, USER_AGENT
from siotls.utils import intbyte

from . import happy_eyeballs


class WallClockTimeoutError(TimeoutError):
    pass


# This function looks long and complicated but really isn't that much.
#
# It really is only about sending a single HTTP request and getting the
# response. What makes it complicated are all the safeguards we added
# due to the high profile of siotls, safeguards that typically are not
# found in other (synchronous) http libraries. They include: wall-clock
# timeout, strict http/1.1, head and body length limits, happy eyesball.
# As this function is called *while establishing a TLS connection* we
# can only use insecure raw HTTP/1. This means that we are prone to a
# very wide range of attacks: we could very well be connecting to a
# rogue HTTP server pretending to be digicert, and who will send a huge
# response at a very slow rate.
#
# We could have split this huge function into many smaller ones, but the
# complexity would essentially have remained the same, just you would
# be scrolling up and down much more. Just bear with it and remember
# that it is only 200ish lines long. That http.client + urllib are much
# longer. Because you did read http.client and urllib(3) before using
# the infamous requests library, right? right?!

def safe_request(  # noqa: C901, PLR0912, PLR0913, PLR0915
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
                        raise TLSError(e)
                    data = sockrecv(min(
                        chunk_length, response_head_max_length))
                    bytes_recv += len(data)
                    conn.receive_data(data)
                case h11.Response():
                    break
                case h11.ConnectionClosed():
                    e = f"{err}: connection closed by peer"
                    raise TLSError(e)
                case _:
                    e = f"{err}: unexpected event: {event}"
                    raise TLSError(e)

        # Make sure we got a 200 with a good CT-Length and CT-Type
        http_res = event
        if http_res.status_code != HTTPStatus.OK:
            e =(f"{err}: bad response status, expected 200, got "
                f"{HTTPStatus(http_res.status_code)!r}")
            raise TLSError(e)

        content_length = http_res.headers.get(b'content-length')
        if content_length is None:
            e = f"{err}: missing mandatory response Content-Length"
            raise TLSError(e)

        content_length = int(content_length)  # h11 validated it
        if content_length > response_body_max_length:
            e =(f"{err}: bad response Content-Length, expected at most "
                f"{response_body_max_length}, got {content_length}")
            raise TLSError(e)

        content_type = http_res.headers.get(b'content-type')
        if content_type != response_content_type:
            e =(f"{err}: bad response Content-Type, expected "
                f"{response_content_type}, got {content_type}")
            raise TLSError(e)

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
                    raise TLSError(e)

    except OSError as exc:
        e = f"{err}: connection failure"
        raise TLSError(e) from exc

    except h11.RemoteProtocolError as exc:
        e = f"{err}: bad http response"
        raise TLSError(e) from exc

    except TimeoutError as exc:
        kind = ( "connection (conn)" if not sock
            else "wall-clock (http)" if isinstance(exc, WallClockTimeoutError)
            else "tcp read/write (sock)")
        e = f"{err}: {kind} timeout"
        raise TLSError(e) from exc

    else:
        return body

    finally:
        if sock is not None:
            sock.close()
