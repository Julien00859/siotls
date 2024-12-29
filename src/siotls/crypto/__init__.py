import pkgutil

from .ciphers import TLSCipherSuite
from .key_exchanges import TLSKeyExchange
from .signatures import TLSSignatureSuite


def install(provider):
    fqmn = f'siotls.crypto.providers.{provider}'
    pkgutil.find_loader(fqmn).load_module(fqmn)
