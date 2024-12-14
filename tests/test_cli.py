import socket
import subprocess as sp
import sys
import unittest
from os import fspath

from . import TAG_INTEGRATION, TestCase, test_temp_dir


@unittest.skipUnless(TAG_INTEGRATION, "enable with SIOTLS_INTEGRATION=1")
class TestExample(TestCase):
    def test_simple_server(self):
        # get a ephemeral free port
        with socket.create_server(('::1', 0), family=socket.AF_INET6, backlog=0) as sock:
            port = sock.getsockname()[1]

        server = sp.Popen(
            [
                sys.executable, '-m', 'siotls',
                'server',
                '-v',
                '--host', '::1',
                '--port', str(port),
                '--tlscert', fspath(test_temp_dir/'server-cert.pem'),
                '--tlskey', fspath(test_temp_dir/'server-privkey.pem'),
            ],
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )
        print(server.stderr.readline())

        client = sp.Popen(
            [
                sys.executable, '-m', 'siotls',
                'server',
                '--host', '::1',
                '--port', str(port),
                '--tlscert', fspath(test_temp_dir/'server-cert.pem'),
                '--tlskey', fspath(test_temp_dir/'server-privkey.pem'),
            ],
            stdout=sp.PIPE,
            stderr=sp.PIPE,
        )
