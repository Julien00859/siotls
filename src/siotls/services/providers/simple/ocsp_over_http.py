import logging
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from siotls import USER_AGENT

from . import OCSPService, OCSPServiceError
from .cache import SieveCache

logger = logging.getLogger(__name__)

OCSP_REQUEST_MIMETYPE = 'application/ocsp-request'
OCSP_RESPONSE_MIMETYPE = 'application/ocsp-response'


class OcspOverHttp(OCSPService):
    cache_cls = SieveCache
    timeout = 1
    stale = 10
    max_response_size = 20480  # 20kiB

    def __init__(self, *, cache_cls=None, timeout=None):
        self._cache = (cache_cls or self.cache_cls)()
        if timeout:
            self.timeout = timeout

    def request(self, url, ocsp_req):
        cached_ocsp_res, expiration = self._cache.get(ocsp_req, (None, None))
        if cached_ocsp_res:
            if datetime.now(UTC) < expiration - timedelta(seconds=self.stale):
                return cached_ocsp_res
            del self._cache[ocsp_req]

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
                'Content-Type': OCSP_REQUEST_MIMETYPE,
                'Host': urlobj.netloc,
                'User-Agent': USER_AGENT,
            }
        )
        try:
            http_res = urlopen(http_req, timeout=self.timeout)  # noqa: S310
            # timeout is per recv, not globally, it can be abused to DOS
        except OSError as exc:
            e = "connection failure"
            raise OCSPServiceError(e) from exc
        except HTTPError as exc:
            e = "http failure"
            raise OCSPServiceError(e) from exc

        content_type = http_res.getheader('Content-Type', OCSP_RESPONSE_MIMETYPE)
        if content_type != OCSP_RESPONSE_MIMETYPE:
            e = f"expected {OCSP_RESPONSE_MIMETYPE}, got {content_type}"
            raise OCSPServiceError(e)

        content_length = int(http_res.getheader('Content-Length', self.max_response_size))
        if content_length > self.max_response_size:
            e = "http response body too large"
            raise OCSPServiceError(e)

        return http_res.read(content_length)

    def save(self, ocsp_req, ocsp_res, until):
        self._cache[ocsp_req] = (ocsp_res, until)

    def delete(self, ocsp_req):
        self._cache.pop(ocsp_req, None)
