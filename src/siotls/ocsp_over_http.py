import heapq
import logging
from datetime import datetime
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import siotls

logger = logging.getLogger(__name__)

CACHE_ENTRIES = 64  # arbitrary
OCSP_MAX_RESPONSE_SIZE = 20480  # 20kiB, arbitrary
USER_AGENT = f"python-siotls/{siotls.__version__}"
TIMEOUT = 1

_cache = {}
_cache_limits = []

def request(url, ocsp_req):
    cached_ocsp_res, cached_until = _cache.get(ocsp_req, (None, None))
    if cached_ocsp_res:
        if datetime.utcnow() < cached_until:  # noqa: DTZ003
            logger.debug('cache hit')
            return cached_ocsp_res
        logger.debug('cache expired')
        del _cache[ocsp_req]
    else:
        logger.debug('cache miss')

    urlobj = urlsplit(url)
    if urlobj.scheme != 'http':
        e = "url scheme must be http"
        raise ValueError(e)
    if not urlobj.netloc:
        e = "url authority cannot be empty"
        raise ValueError(e)
    if not ocsp_req:
        e = "empty ocsp request"
        raise ValueError(e)

    logger.info("requesting online certificate status at %s", url)
    http_req = Request(  # noqa: S310
        url,
        ocsp_req,
        headers={
            'Content-Type': 'application/ocsp-request',
            'Host': urlobj.netloc,
            'User-Agent': USER_AGENT,
        }
    )
    http_res = urlopen(http_req, timeout=TIMEOUT)  # noqa: S310
    # timeout is per recv, not globally, it can be abused to DOS

    content_type = http_res.getheader('Content-Type', 'application/ocsp-response')
    if content_type != 'application/ocsp-response':
        e =(f"unsupported HTTP response type: {content_type}")
        raise RuntimeError(e)

    content_length = int(http_res.getheader('Content-Length', OCSP_MAX_RESPONSE_SIZE))
    if content_length > OCSP_MAX_RESPONSE_SIZE:
        e =(f"OCSP response body too large ({content_length} bytes vs "
            f"{OCSP_MAX_RESPONSE_SIZE} bytes)")
        raise RuntimeError(e)

    return http_res.read(content_length)


def cache(until, ocsp_req, ocsp_res):
    if ocsp_req in _cache:
        return
    while len(_cache_limits) >= CACHE_ENTRIES:
        uncache(heapq.heappop(_cache_limits)[1])
    heapq.heappush(_cache_limits, (until, ocsp_req))
    _cache[ocsp_req] = (ocsp_res, until)


def uncache(ocsp_req):
    _cache.pop(ocsp_req, None)
