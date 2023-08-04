import argparse
import getpass
import importlib.resources
import logging
import mimetypes
import pathlib
import os
import sys
import warnings

import onioncorn
import onioncorn.server


logger = logging.getLogger(__name__)


def main():
    mimetypes.init()
    parser = argparse.ArgumentParser(prog=__package__)
    parser.add_argument('-V', '--version', action='version',
        version=f'%(prog)s {onioncorn.__version__}')
    parser.add_argument('-v', '--verbose', action='count', default=0,
        help="Increase logging verbosity (repeatable)")
    parser.add_argument('-s', '--silent', action='count', default=0,
        help="Decrease logging verbosity (repeatable)")
    parser.add_argument('port', action='store', type=int,
        help="TCP port number on which the server will listen")
    parser.add_argument('--tlscert', '--sslcert', action='store', type=pathlib.Path,
        default=importlib.resources.path('onioncorn.data', 'self-signed-cert.pem'),
        help="Path to the SSL/TLS certificate file")
    parser.add_argument('--tlskey', '--sslkey', action='store', type=pathlib.Path,
        default=importlib.resources.path('onioncorn.data', 'self-signed-key.pem'),
        help="Path to the SSL/TLS private key file")

    try:
        options = parser.parse_args()
    except Exception as exc:
        logging.basicConfig(level=logging.CRITICAL)
        logging.critical("Couldn't parse command line", exc_info=exc)
        return 1

    setup_logging(logging.INFO - options.verbose * 10 + options.silent * 10)

    # Check TLS cert/key
    if not os.access(options.tlscert, os.R_OK):
        logging.critical("Cannot access TLS certificate file at %s", options.tlscert)
        return 1
    if not os.access(options.tlskey, os.R_OK):
        logging.critical("Cannot access TLS private key file at %s", options.tlscert)
        return 1
    if any(
        self_signed_hint in file.name.replace('-', '').replace('_', '')
        for file in [options.tlskey, options.tlscert]
        for self_signed_hint in ['snakeoil', 'selfsigned']
    ):
        logger.warning("Looks like your TLS key/cert is self-signed, unwise for production.")
    elif options.tlskey.stat().st_mode & 0o66:
        logging.critical(
            "The TLS private key file at %s has too broad permissions, it should only be "
            "readable by the current user %r. In case you are using a self-signed certificate "
            "for development, please rename it as %r or leave out the option to use the "
            "self-signed certificate/private key bundled with onioncorn.",
            options.tlskey,
            getpass.getuser(),
            options.tlskey.with_stem(f"{options.tlskey.stem}-self-signed").name
        )
        return 1

    # Run server
    try:
        onioncorn.server.serve(options.port, os.fspath(options.tlscert), os.fspath(options.tlskey))
    except Exception as exc:
        logger.critical("Fatal exception while running the server", exc_info=exc)
        return 1

    return 0


# Color the [LEVEL] part of messages, need new terminal on Windows
# https://github.com/odoo/odoo/blob/13.0/odoo/netsvc.py#L57-L100
class ColoredFormatter(logging.Formatter):
    colors = {
        logging.DEBUG: (34, 49),  # blue
        logging.INFO: (32, 49),  # green
        logging.WARNING: (33, 49),  # yellow
        logging.ERROR: (31, 49),  # red
        logging.CRITICAL: (37, 41),  # white fg, red bg
    }
    def format(self, record):
        fg, bg = type(self).colors.get(record.levelno, (32, 49))
        record.levelname = f'\033[1;{fg}m\033[1;{bg}m{record.levelname}\033[0m'
        return super().format(record)


def setup_logging(verbosity):
    stderr = logging.StreamHandler()
    stderr.formatter = (
        ColoredFormatter('[%(levelname)s] %(message)s')
        if hasattr(sys.stderr, 'fileno') and os.isatty(sys.stderr.fileno()) else
        logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    )
    root_logger = logging.getLogger('' if __name__ == '__main__' else __package__)
    root_logger.handlers = [stderr]
    root_logger.setLevel(max(verbosity, logging.DEBUG))
    if verbosity < logging.DEBUG:
        logging.captureWarnings(capture=True)
        warnings.filterwarnings("default")

if __name__ == '__main__':
    sys.exit(main())
