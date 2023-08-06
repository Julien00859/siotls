import io
import logging
import struct
from functools import partial
from pprint import pp
from socket import socket
from siotls.iana import *
from siotls.utils import hexdump, ExactBytesIO

logger = logging.getLogger(__name__)

def handle_one(client, client_info):
    buffer = b''
    while message := client.recv(1024):
        logger.info("%s bytes from %s:\n%s", len(message), client_info[1], hexdump(message))

        buffer += message
        if len(buffer) < 5:
            continue
        length = (buffer[3] << 8) + buffer[4]
        if len(buffer) - 5 < length:
            continue

        data, buffer = buffer[:length+5], buffer[length+5:]
        stream = ExactBytesIO(data)
        read = stream.read_exactly

        record = __import__('types').SimpleNamespace()
        handshake = __import__('types').SimpleNamespace()
        record.type = ContentType(ord(read(1)))
        record.version = TLSVersion(int.from_bytes(read(2), 'big'))
        record.length = int.from_bytes(read(2), 'big')
        assert record.type == ContentType.HANDSHAKE

        handshake.type = HandshakeType(ord(read(1)))
        handshake.length = int.from_bytes(read(3), 'big')
        assert handshake.type == HandshakeType.CLIENT_HELLO

        handshake.version = TLSVersion(int.from_bytes(read(2), 'big'))
        handshake.random = read(32)
        handshake.session_id = read(ord(read(1)))
        handshake.cipher_suites = list(map(CipherSuites, zip(it:=iter(read(int.from_bytes(read(2), 'big'))), it)))
        handshake.compression_methods = read(ord(read(1)))
        handshake.extensions = []

        extensions_length = int.from_bytes(read(2), 'big')
        while extensions_length:
            extension = __import__('types').SimpleNamespace()
            extension.type = int.from_bytes(read(2), 'big')
            try:
                extension.type = ExtensionType(extension.type)
            except ValueError:
                pass
            length = int.from_bytes(read(2), 'big')
            extension.data = stream.read(length)
            handshake.extensions.append(vars(extension))
            extensions_length -= length + 4

        pp(vars(record))
        pp(vars(handshake))



def serve(port, tlscert, tlskey):
    server = socket()
    server.bind(('localhost', port))
    server.listen(1)
    logger.info("listening on %s", port)

    try:
        while True:
            client = None
            client, client_info = server.accept()
            logger.info("new connection from %s", client_info[1])
            handle_one(client, client_info)
            logger.info("end of connection with %s", client_info[1])
    except KeyboardInterrupt:
        logger.info("closing server")
    finally:
        if client:
            client.close()
        server.close()
