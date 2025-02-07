import logging
import os.file
import platform
import ssl
from pathlib import Path

from cryptography.x509 import load_pem_x509_certificate, load_pem_x509_certificates
from cryptography.x509.verification import Store

logger = logging.getLogger(__name__)

LINUX_CA_CERTIFICATES_PATHS = {
    'alpine': '/etc/ssl/certs/ca-certificates.crt',
    'arch': '/etc/ca-certificates/extracted/tls-ca-bundle.pem',
    'debian': '/etc/ssl/certs/ca-certificates.crt',
    'fedora': '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
    'suse': '/var/lib/ca-certificates/ca-bundle.pem',
    'ubuntu': '/etc/ssl/certs/ca-certificates.crt',
}


def get_trust_store():
    defaults = ssl.get_default_verify_paths()
    if defaults.cafile:
        return Store(load_pem_x509_certificates(Path(defaults.cafile).read_bytes()))
    if defaults.cacert:
        return Store([
            load_pem_x509_certificate(path.read_bytes())
            for path
            in Path(defaults.cacert).iterdir()
            if path.suffix == '.pem'
        ])

    s =(f"invalid/missing environment variables {defaults.openssl_cafile_env}"
        f"and {defaults.openssl_capath_env}")

    if platform.system() == 'Linux':
        release_id, linux_cafile = _get_linux_cafile(platform.freedesktop_os_release())
        if linux_cafile:
            w = s + ", detected linux system like %s, using %s"
            logger.warning(w, release_id, linux_cafile)
            return Store(load_pem_x509_certificates(Path(linux_cafile).read_bytes()))

    e = s + ", could not load a trust store"
    raise RuntimeError(e)


def _get_linux_cafile(release):
    release.setdefault('ID_LIKE', '')
    for release_id in [release['ID'], *release['ID_LIKE'].split()]:
        path = LINUX_CA_CERTIFICATES_PATHS.get(release_id)
        if path and os.path.isfile(path):
            return release_id, path
    return release['ID'], None
