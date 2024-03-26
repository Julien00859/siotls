import platform
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificates
from cryptography.x509.verification import Store


def build_system_store():
    system = platform.system()
    if system == 'Linux':
        return _build_linux_store()

    e = f"the system {system!r} is not supported yet"
    raise NotImplementedError(e)


def _build_linux_store():
    return Store(load_pem_x509_certificates(
        Path('/etc/ssl/certs/ca-certificates.crt').read_bytes()
    ))


def build_certify_store():
    import certifi
    return Store(load_pem_x509_certificates(
        Path(certifi.where()).read_bytes()
    ))
