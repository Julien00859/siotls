import argparse
import getpass
import importlib.resources
import logging
import mimetypes
import os
import pathlib
import sys
import warnings
from socket import socket

import siotls

def hexdump(bytes_):
    """
    Produce a pretty hexdump suitable for human reading

    >>> hexdump(b'\x00\x17Hello world!\nSweat day.\x00')
    '''\
    0000: 00 17 48 65 6c 6c 6f 20  77 6f 72 6c 64 21 0a 53  ..Hello  world!.S
    0010: 77 65 61 74 20 64 61 79  2e 00                    weat day ..'''
    """
    it = iter(bytes_)
    xd = bytearray()
    hex_ = bytearray()
    d = math.ceil(math.ceil(len(bytes_).bit_length() / 4) / 4) * 4
    i = 0
    while line := bytes(itertools.islice(it, 16)):
        hex_.clear()
        hex_.extend(binascii.hexlify(line[:8], ' '))
        hex_.extend(b'  ')
        hex_.extend(binascii.hexlify(line[8:], ' '))
        hex_.extend(b'  ')
        hex_.extend(b' ' * (50 - len(hex_)))  # 3 * 16 + 2
        xd.extend(f'{i:0{d}x}: '.encode())
        xd.extend(hex_)
        xd.extend([byte if 32 <= byte <= 126 else 46 for byte in line[:8]])
        xd.extend(b' ')
        xd.extend([byte if 32 <= byte <= 126 else 46 for byte in line[8:]])
        xd.extend(b'\n')
        i += 16
    if bytes_:
        xd.pop()  # ditch last \n
    return xd.decode()


def serve(port, tlscert, tlskey):
    logger = logging.getLogger(f'{__package__}.serve')

    server = socket()
    server.bind(('localhost', port))
    server.listen(1)
    logger.info("listening on %s", port)

    try:
        while True:
            client = None
            client, client_info = server.accept()
            logger.info("new connection from %s", client_info[1])

            while message := client.recv(1024):
                logger.info("%s bytes from %s:\n%s", len(message), client_info[1], hexdump(message))
            logger.info("end of connection with %s", client_info[1])
    except KeyboardInterrupt:
        logger.info("closing server")
    finally:
        if client:
            client.close()
        server.close()



def main():
    mimetypes.init()
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

    # Run server
    try:
        serve(options.port, os.fspath(options.tlscert), os.fspath(options.tlskey))
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
