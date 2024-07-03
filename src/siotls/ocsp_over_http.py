import abc
import heapq
import logging
from datetime import datetime
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from siotls.utils import USER_AGENT

logger = logging.getLogger(__name__)


class OCSPService(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def request(self, url: str, ocsp_req: bytes) -> datetime:
        raise NotImplementedError  # pragma: no cover

    def cache(self, until, ocsp_req, ocsp_res):  # noqa: B027
        pass  # pragma: no cover

    def uncache(self, ocsp_req):  # noqa: B027
        pass  # pragma: no cover


class OcspOverHttp(OCSPService):
    timeout = 1
    max_cache_entries = 64
    max_response_size = 20480  # 20kiB

    def __init__(self):
        self._cache = {}
        self._cache_limits = []

    def request(self, url, ocsp_req):
        cached_ocsp_res, cached_until = self._cache.get(ocsp_req, (None, None))
        if cached_ocsp_res:
            if datetime.utcnow() < cached_until:  # noqa: DTZ003
                logger.debug('cache hit')
                return cached_ocsp_res
            logger.debug('cache expired')
            del self._cache[ocsp_req]
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
        http_res = urlopen(http_req, timeout=self.timeout)  # noqa: S310
        # timeout is per recv, not globally, it can be abused to DOS

        content_type = http_res.getheader('Content-Type', 'application/ocsp-response')
        if content_type != 'application/ocsp-response':
            e =(f"unsupported HTTP response type: {content_type}")
            raise RuntimeError(e)

        content_length = int(http_res.getheader('Content-Length', self.max_response_size))
        if content_length > self.max_response_size:
            e =(f"OCSP response body too large ({content_length} bytes vs "
                f"{self.max_response_size} bytes)")
            raise RuntimeError(e)

        return http_res.read(content_length)

    def cache(self, until, ocsp_req, ocsp_res):
        if ocsp_req in self._cache:
            return
        while len(self._cache_limits) >= self.max_cache_entries:
            self.uncache(heapq.heappop(self._cache_limits)[1])
        heapq.heappush(self._cache_limits, (until, ocsp_req))
        self._cache[ocsp_req] = (ocsp_res, until)

    def uncache(self, ocsp_req):
        self._cache.pop(ocsp_req, None)
