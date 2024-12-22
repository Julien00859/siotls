import contextlib
import logging
import pathlib
import random
import tempfile
from datetime import UTC, datetime, timedelta
from http import HTTPStatus
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from siotls import USER_AGENT

from . import TLSService, TLSServiceError, TLSServiceErrorGroup

logger = logging.getLogger(__name__)

CRL_MIMETYPE = 'application/pkix-crl'



class _CacheMixin:
    stale: timedelta
    cache_cls = SieveCache

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = self.cache_cls()

    def _cache_get(self, key, default=None):
        data, expire = self._cache.get(key, (None, None))
        if not data:
            return default
        now = datetime.now(UTC)
        if now > expire - stale:
            self._cache_del(key)
            return default
        return data

    def _cache_set(self, key, data, expire):
        self._cache[key] = (data, expire)

    def _cache_del(self, key):
        self._cache.pop(key)


class _RequestMixin:
    timeout: int = 1
    request_content_type: str
    response_content_type: str
    request_max_length: int
    response_max_length: int
    response_chunk_length: int = 1 << 14  # 16kiB

    def _log_request(self, urlobj, http_req, http_res=None, status=None):
        bad = status or http_res.status >= 400  # noqa: PLR2004
        logger.log(
            logging.WARNING if bad else logging.INFO,
            '%(host)s - - [%(now)s] "%(method)s %(path)s HTTP/1.1" %(status)s %(length)s',
            host=http_req.host,
            now=datetime.now(UTC).strftime('%d/%b/%Y:%H:%M:%S %z'),
            method='POST' if http_req.data else 'GET',
            path=f'{urlobj.path}?{urlobj.query}',
            status=status or http_res.status,
            length=http_res.getheader('Content-Length', '-') if http_res else '',
        )

    def _request(self, url, data=None):
        urlobj = urlsplit(url)
        if urlobj.scheme != 'http':
            e = "url scheme must be http"
            raise ValueError(e)
        if not urlobj.netloc:
            e = "url authority cannot be empty"
            raise ValueError(e)

        headers = {
            'Host': urlobj.netloc,
            'User-Agent': USER_AGENT,
        }
        if data is not None:
            if len(data) > self.request_max_length:
                e = "request body too large"
                raise ValueError(e)
            headers['Content-Type'] = self.request_content_type
            headers['Content-Length'] = len(data)

        http_req = Request(url, data, headers=headers)  # noqa: S310
        try:
            http_res = urlopen(http_req, timeout=self.timeout)  # noqa: S310
            # timeout is per recv, not globally, it can be abused to DOS
        except OSError as exc:
            self._log_request(urlobj, http_req, None, exc.args[0])
            e = "connection failure"
            raise TLSServiceError(e) from exc
        except HTTPError as exc:
            self._log_request(urlobj, http_req, exc)
            e = "http failure"
            raise TLSServiceError(e) from exc
        else:
            self._log_request(urlobj, http_req, http_res)

        if http_res.status == HTTPStatus.NO_CONTENT:
            return http_res, b''

        content_type = http_res.getheader('Content-Type', self.response_content_type)
        if content_type != self.response_content_type:
            e = f"expected {self.response_content_type}, got {content_type}"
            raise TLSServiceError(e)

        content_length = int(http_res.getheader('Content-Length', self.response_max_length))
        if content_length > self.response_max_length:
            e = "http response body too large"
            raise TLSServiceError(e)

        if content_length <= self.response_chunk_length:
            return http_res, http_res.read(content_length)

        body = bytearray()
        while chunk := http_res.read(self.response_chunk_length):
            if len(body) + len(chunk) > content_length:
                e = "http response body too large"
                raise TLSServiceError(e)
            body += chunk

        return http_res, body


class OCSPService(TLSService, _RequestMixin):
    request_content_type = 'application/ocsp-request'
    response_content_type = 'application/ocsp-response'
    request_max_length = 512
    response_max_length = 1 << 15  # 32kiB, longest ocsp res I have is 12kiB

    def request(self, url, ocsp_req):
        if ocsp_res := self._cache_get(ocsp_req):
            return ocsp_res

        http_res, ocsp_res = self._request(url, ocsp_req)

        ocsp_res_obj = ...
        expire = ... # nextUpdate or now+maxage or expires
        if expire:
            self._cache_set(ocsp_req, ocsp_res, expire)

        return ocsp_res

    def delete(self, url, ocsp_req):  # noqa: ARG002
        self._cache_del(ocsp_req)

class CRTService(TLSService, _RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = ...
    response_max_length = 1 << 15  # 32kiB, longest cert chain I have is 16kiB


class CRLService(TLSService, _RequestMixin):
    request_content_type = ''
    request_max_length = 0

    response_content_type = ...
    response_max_length = 1 << 24  # 16MiB, longest crl I have (DigitCert) is 7MiB

