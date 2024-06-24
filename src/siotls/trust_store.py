import platform

from cryptography.x509 import load_pem_x509_certificates
from cryptography.x509.verification import Store

LINUX_CA_CERTIFICATES_PATHS = {
    'alpine': '/etc/ssl/certs/ca-certificates.crt',
    'arch': '/etc/ca-certificates/extracted/tls-ca-bundle.pem',
    'debian': '/etc/ssl/certs/ca-certificates.crt',
    'fedora': '/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
    'suse': '/var/lib/ca-certificates/ca-bundle.pem',
    'ubuntu': '/etc/ssl/certs/ca-certificates.crt',
}


def get_system_store():
    match platform.system():
        case 'Linux':
            ca_cert_path = get_ca_certificates_path(platform.freedesktop_os_release())
            with open(ca_cert_path, 'rb') as ca_cert_file:
                return Store(load_pem_x509_certificates(ca_cert_file.read()))
        case 'Darwin':
            return get_darwin_store()
        case 'Java':
            return get_java_store()
        case 'Windows':
            return get_windows_store()
        case system:
            e = f"unknown operating system: {system}"
            raise ValueError(e)


def get_ca_certificates_path(release):
    release.setdefault('ID_LIKE', '')
    for release_id in [release['ID'], *release['ID_LIKE'].split()]:
        path = LINUX_CA_CERTIFICATES_PATHS.get(release_id)
        if path:
            return path
    e = f"unknown linux system {release['ID']!r} (like {release['ID_LIKE']})"
    raise ValueError(e)


def get_darwin_store():
    raise NotImplementedError


def get_java_store():
    raise NotImplementedError


def get_windows_store():
    raise NotImplementedError
