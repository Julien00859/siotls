import abc
from collections.abc import Iterable
from datetime import datetime

from siotls import TLSError


class TLSServiceError(TLSError):
    pass

class TLSServiceErrorGroup(ExceptionGroup, TLSServiceError):  # noqa: N818
    pass
