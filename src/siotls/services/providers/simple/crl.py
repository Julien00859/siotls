import logging

from siotls.services import TLSService
from siotls.services.filestore import FileStore
from siotls.utils import intbyte

from ._mixins import CacheMixin, RequestMixin

logger = logging.getLogger(__package__)

class CRLService(TLSService, CacheMixin, RequestMixin):
    cache_cls = FileStore

    request_content_type = ''
    request_max_length = 0

    response_content_type = b'application/pkix-crl'
    response_max_length = intbyte('16MiB')  # longest crl I have (DigitCert) is 7MiB

    def request(self, *a, **kw):
        raise NotImplementedError("todo")  # noqa: EM101
