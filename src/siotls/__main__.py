import argparse
import importlib.resources
import logging
import os
import pathlib
import sys
import warnings

import siotls
import siotls.examples.simple

logger = logging.getLogger(__name__)


# Color the LEVEL part of messages, need new terminal on Windows
class ColoredFormatter(logging.Formatter):
    colors = {
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


def main():
    logging.basicConfig()

    parser = argparse.ArgumentParser(prog=__package__)
    parser.add_argument('-V', '--version', action='version',
        version=f'%(prog)s {siotls.__version__}')
    parser.add_argument('-v', '--verbose', action='count', default=0,
        help="Increase logging verbosity (repeatable)")
    parser.add_argument('-s', '--silent', action='count', default=0,
        help="Decrease logging verbosity (repeatable)")
    parser.add_argument('port', action='store', type=int,
        help="TCP port number on which the server will listen")
    parser.add_argument('--tlscert', '--sslcert', action='store', type=pathlib.Path,
        default=importlib.resources.path('siotls.data', 'self-signed-cert.pem'),
        help="Path to the SSL/TLS certificate file")
    parser.add_argument('--tlskey', '--sslkey', action='store', type=pathlib.Path,
        default=importlib.resources.path('siotls.data', 'self-signed-key.pem'),
        help="Path to the SSL/TLS private key file")

    try:
        options = parser.parse_args()
    except Exception as exc:
        logging.critical("Couldn't parse command line", exc_info=exc)
        return 1

    # Configure logging
    if hasattr(sys.stderr, 'fileno') and os.isatty(sys.stderr.fileno()):
        logging.getLogger().handlers[0].formatter = ColoredFormatter(logging.BASIC_FORMAT)
    verbosity = logging.INFO - options.verbose * 10 + options.silent * 10
    logging.getLogger().setLevel(max(verbosity, logging.DEBUG))
    if verbosity < logging.DEBUG:
        logging.captureWarnings(True)
        warnings.filterwarnings("default")

    # Check TLS cert/key
    if not os.access(options.tlscert, os.R_OK):
        logging.critical("Cannot access TLS certificate file at %s", options.tlscert)
        return 1
    if not os.access(options.tlskey, os.R_OK):
        logging.critical("Cannot access TLS private key file at %s", options.tlscert)
        return 1

    # Run server
    try:
        siotls.examples.simple.serve(
            options.port,
            os.fspath(options.tlscert),
            os.fspath(options.tlskey),
        )
    except Exception as exc:
        logger.critical("Fatal exception while running the server", exc_info=exc)
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
