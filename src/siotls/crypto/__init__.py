import pkgutil

from .cipher_suites import TLSCipherSuite
from .key_exchanges import TLSKeyExchange
from .signature_schemes import TLSSignatureScheme


def install(provider):
    fqmn = f'siotls.crypto.providers.{provider}'
    pkgutil.find_loader(fqmn).load_module(fqmn)
