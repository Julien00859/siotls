import contextlib
import logging
import pathlib
import random
import tempfile
from datetime import UTC, datetime, timedelta
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from siotls import USER_AGENT

from . import CRLService, CRLServiceError, CRLServiceErrorGroup

logger = logging.getLogger(__name__)

CRL_MIMETYPE = 'application/pkix-crl'


class CrlOverHttp(CRLService):
    folder = pathlib.Path(tempfile.gettempdir())
    timeout = 1
    stale = 10
    chunk_size = 1 << 14  # 16kiB
    max_response_size = 1 << 24  # 16MiB

    def __init__(self):
        self._cache = {}  # {url: (crl_path, expiration)}

    def _local_path(self, url):
        urlobj = urlsplit(url)
        filename = urlobj.path.rpartition('/')[2]
        if not filename:
            filename = urlobj.hostname.replace('.', '-') + '.crl'
        return self.folder.joinpath(filename)

    def get(self, urls):
        # Try to get the CRL from the cache first
        utcnow = datetime.now(UTC)
        for url in urls:
            crl_path, expiration = self._cache.get(url, (None, None))
            if crl_path:
                is_fresh = utcnow < expiration - timedelta(seconds=self.state)
                if is_fresh:
                    with contextlib.suppress(OSError):
                        crl_data = crl_path.read_bytes()
                        logger.info("using revocation list found at %s", crl_path)
                        return url, crl_data
                self.delete(url)

        # Lookup the disk folder, but the CRL might be outdated...
        for url in urls:
            with contextlib.suppress(OSError):
                crl_path = self._local_path(url)
                crl_data = crl_path.read_bytes()
                logger.info("using revocation list found at %s", crl_path)
                return url, crl_data

        return None, None

    def save(self, url, crl, expiration):
        crl_path = self._local_path(url)
        if not crl_path.is_file():
            logger.info("saving revocation list at %s", crl_path)
            crl_path.write_bytes(crl)
        self._cache[url] = (crl_path, expiration)

    def delete(self, url):
        crl_path, _ = self._cache.pop(url, (None, None))
        if crl_path:
            crl_path.unlink(missing_ok=True)

    def request(self, urls):
        if not urls:
            e = "missing url"
            raise ValueError(e)

        if len(urls) == 1:
            return urls[0], self._request_single(urls[0])

        # Trying each URL sequentially isn't very effective... Ideally
        # we should do as many concurrent happy-eyeballs (RFC8305) as
        # there are URLs. So we can download from the single best one.
        random.shuffle(urls)  # don't always reach for the first one
        exc = None
        excs = []
        for url in urls:
            try:
                return url, self._request_single(url)
            except CRLServiceError as exc_:
                exc = exc_
            excs.append(exc)
        e = "all URLs failed"
        raise CRLServiceErrorGroup(e, excs)

    def _request_single(self, url):
        urlobj = urlsplit(url)
        if urlobj.scheme != 'http':
            e = "url scheme must be http"
            raise ValueError(e)
        if not urlobj.netloc:
            e = "url authority cannot be empty"
            raise ValueError(e)

        logger.info("downloading revocation list from %s", url)
        http_req = Request(  # noqa: S310
            url,
            headers={
                'Host': urlobj.netloc,
                'User-Agent': USER_AGENT,
            }
        )
        try:
            http_res = urlopen(http_req, timeout=self.timeout)  # noqa: S310
            # timeout is per recv, not globally, it can be abused to DOS
        except OSError as exc:
            e = "connection failure"
            raise CRLServiceError(e) from exc
        except HTTPError as exc:
            e = "http failure"
            raise CRLServiceError(e) from exc

        content_type = http_res.getheader('Content-Type', CRL_MIMETYPE)
        if content_type != CRL_MIMETYPE:
            e = f"expected {CRL_MIMETYPE}, got {content_type}"
            raise CRLServiceError(e)

        content_length = int(http_res.getheader('Content-Length', self.max_response_size))
        if content_length > self.max_response_size:
            e = "http response body too large"
            raise CRLServiceError(e)

        return http_res.read(content_length)
