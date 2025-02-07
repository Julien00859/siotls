import logging
import random

from siotls.services import TLSService, TLSServiceError, TLSServiceErrorGroup
from siotls.services.filestore import FileStore
from siotls.utils import intbyte
from siotls.x509 import load_der_certificate

from ._mixins import CacheMixin, RequestMixin

logger = logging.getLogger(__package__)


class CRTService(TLSService, RequestMixin, CacheMixin):
    cache_cls = FileStore

    request_content_type = ''
    request_max_length = 0

    response_content_type = b'application/pkix-cert'
    response_max_length = intbyte('64kiB')  # longest cert chain I have is 16kiB

    def request(self, urls):
        if not urls:
            e = "missing url"
            raise ValueError(e)

        for url in urls:
            if cert := self._cache_get(url):
                return cert

        if len(urls) == 1:
            return self._request_single(urls[0])

        # Trying each URL sequentially isn't very effective... Ideally
        # we should do as many concurrent happy-eyeballs (RFC8305) as
        # there are URLs. So we can download from the single best one.
        random.shuffle(urls)  # don't always reach for the first one
        excs = []
        for url in urls:
            try:
                return self._process(self._request(url))
            except TLSServiceError as exc:
                excs.append(exc)
                continue
        e = "all URLs failed"
        raise TLSServiceErrorGroup(e, excs)

    def _process(self, cert_res):
        try:
            cert = load_der_certificate(cert_res)
        except ValueError as exc:
            e = "error while loading certificate"
            raise TLSServiceError(e) from exc

        return cert_res
