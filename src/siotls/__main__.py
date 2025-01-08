import argparse
import logging
import os
import pathlib
import pkgutil
import sys
import warnings

import siotls
import siotls.crypto.providers
import siotls.services.providers

logger = logging.getLogger(__name__)


# Color the LEVEL part of messages, need new terminal on Windows
class ColoredFormatter(logging.Formatter):
    colors = {  # noqa: RUF012
        logging.DEBUG: (34, 49),  # blue
        logging.INFO: (32, 49),  # green
        logging.WARNING: (33, 49),  # yellow
        logging.ERROR: (31, 49),  # red
        logging.CRITICAL: (37, 41),  # white on red
    }
    def format(self, record):
        fg, bg = type(self).colors.get(record.levelno, (32, 49))
        record.levelname = f'\033[1;{fg}m\033[1;{bg}m{record.levelname}\033[0m'
        record.name = f'\033[1;29m\033[1;49m{record.name}\033[0m'
        return super().format(record)


def setup_logging(verbosity):
    if hasattr(sys.stderr, 'fileno') and os.isatty(sys.stderr.fileno()):
        logging.getLogger().handlers[0].formatter = ColoredFormatter(logging.BASIC_FORMAT)
    logging.getLogger().setLevel(max(verbosity, logging.DEBUG))
    if verbosity < logging.DEBUG:
        logging.captureWarnings(capture=True)
        warnings.filterwarnings("default")


def list_providers(namespace):
    return [
        module.name.rpartition('.')[2]
        for module
        in pkgutil.iter_modules(namespace.__path__, namespace.__name__ + '.')
    ]


def main():
    logging.basicConfig()

    parser = argparse.ArgumentParser(prog=__package__)
    parser.add_argument('-V', '--version', action='version',
        version=f'%(prog)s {siotls.__version__}')
    parser.add_argument('-v', '--verbose', action='count', default=0,
        help="increase logging verbosity (repeatable)")
    parser.add_argument('-s', '--silent', action='count', default=0,
        help="decrease logging verbosity (repeatable)")
    parser.add_argument('side', action='store', choices=('client', 'server'))
    parser.add_argument('--host', action='store', default='::1',
        help="Host / IPv6 address on which the server will listen / client will connect")
    parser.add_argument('--port', action='store', type=int, default=8446,
        help="TCP port number on which the server will listen / client will connect")
    parser.add_argument('--tlscert', '--sslcert', action='store', type=pathlib.Path,
        help="path to the SSL/TLS certificate file")
    parser.add_argument('--tlskey', '--sslkey', action='store', type=pathlib.Path,
        help="path to the SSL/TLS private key file")
    parser.add_argument('--keylogfile', action='store', type=pathlib.Path,
        help="export TLS secrets to the specificed file for network analyzing "
             "tools such as wireshark, use - to log on stderr")
    parser.add_argument('--insecure', action='store_true',
        help="skip verifying the remote certificate")
    parser.add_argument('--crypto-provider', action='store',
        choices=list_providers(siotls.crypto.providers), default='openssl',
        help="the cryptography library that will be used to encrypt the "
             "data on the wire and sign/validate the digital signatures")
    parser.add_argument('--service-provider', action='store',
        choices=list_providers(siotls.services.providers), default='simple',
        help="the http/caching service library that will be used to "
             "download remote CRLs and request OCSP statuses")

    options = parser.parse_args()

    # Configure logging
    verbosity = logging.INFO - options.verbose * 10 + options.silent * 10
    setup_logging(verbosity)

    # Setup SSLKEYLOGFILE
    if not options.keylogfile:
        pass
    elif options.keylogfile.name == '-':
        logger.info("Logging keys on stdout")
        siotls.key_logger.addHandler(logging.StreamHandler())
    else:
        logger.info("Logging keys at %s", options.keylogfile)
        siotls.key_logger.addHandler(logging.FileHandler(options.keylogfile, 'w'))

    # Check TLS cert/key
    if options.tlscert and not os.access(options.tlscert, os.R_OK):
        logging.critical("Cannot access TLS certificate file at %s", options.tlscert)
        return 1
    if options.tlskey and not os.access(options.tlskey, os.R_OK):
        logging.critical("Cannot access TLS private key file at %s", options.tlskey)
        return 1

    # Load the cryptography provider
    siotls.crypto.install(options.crypto_provider)

    # Run
    try:
        if options.side == 'server':
            from siotls.examples.simple_server import serve
            serve(
                options.host,
                options.port,
                os.fspath(options.tlscert),
                os.fspath(options.tlskey),
                log_keys=bool(options.keylogfile),
            )
        else:
            from siotls.examples.simple_client import connect
            connect(
                options.host,
                options.port,
                check_certificate=not options.insecure,
                log_keys=bool(options.keylogfile),
            )
    except Exception:
        logger.critical("Fatal exception")
        raise
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, exiting.")

    return 0


if __name__ == '__main__':
    sys.exit(main())
