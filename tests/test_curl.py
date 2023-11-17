import errno
import os
import shutil
import socket
import subprocess as sp
import tempfile
import unittest
from collections import namedtuple

from siotls import TLSConfiguration, TLSConnection

HOST = '127.0.0.2'
PORT = 8446
CURL_PATH = shutil.which('curl')


@unittest.skipUnless(CURL_PATH, "curl not found in path")
class TestCURL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.socket = socket.socket()
        cls.socket.bind(('localhost', 8446))
        cls.socket.listen(1)
        cls.socket.settimeout(1)
        cls.addClassCleanup(cls.socket.close)

        cls.keylogfile_fd, cls.keylogfile_path = tempfile.mkstemp(
            prefix="siotls-keylogfile-")
        cls.addClassCleanup(os.remove, cls.keylogfile_path)

    def setUp(self):
        # make sure no request is pending
        self.socket.settimeout(0)
        try:
            self.socket.accept()
        except socket.error as exc:
            if exc.errno not in (errno.EAGAIN, errno.ECONNABORTED):
                raise
        self.socket.settimeout(1)

        os.truncate(self.keylogfile_fd, 0)

    def curl(
        self,
        version='1.3',
        max_time=1,
        insecure=True,
        tls_max='1.3',
        options={},
    ):
        args = [CURL_PATH, 'https://localhost:8446']
        if version:
            args.append(f'--tlsv{version}')
        if max_time is not None:
            args.append('--max-time')
            args.append(str(max_time))
        if insecure:
            args.append('--insecure')
        if tls_max is not None:
            args.append('--tls-max')
            args.append(tls_max)
        for option, value in options:
            args.append(f'--{option}')
            args.append(value)
        env = {'SSLKEYLOGFILE': self.keylogfile_path}
        proc = sp.Popen(args, env=env)
        self.addCleanup(proc.terminate)

        client, client_info = self.socket.accept()
        self.addCleanup(client.close)

        return proc, client

    def test_keylogfile(self):
        KeyLogFormat = namedtuple("KeyLogFormat", ["label", "client_random", "value"])

        config = TLSConfiguration('server')
        proc, client = self.curl()

        with self.assertLogs('siotls.keylog', level='INFO') as logs:
            conn = TLSConnection(config, log_keys=True)
            conn.initiate_connection()
            client_hello = client.recv(16384)
            conn.receive_data(client_hello)
            server_hello = conn.data_to_send()
            client.send(server_hello)

        proc.terminate()
        proc.wait(timeout=1)

        siotls_keylog = [
            KeyLogFormat(*line.rpartition(':')[2].split(' '))
            for line in logs.output
            if '#' not in line
        ]

        with open(self.keylogfile_path, 'r') as curl_keyfile:
            curl_keylog = [
                KeyLogFormat(*line.strip().split(' '))
                for line in curl_keyfile.readlines()
                if not line.startswith('#')
            ]

        # Validate labels
        self.assertEqual(
            sorted({log.label for log in siotls_keylog}),
            sorted([log.label for log in siotls_keylog]),
            "There must not be any duplicated label in siotls keylog"
        )
        self.assertEqual(
            sorted({log.label for log in curl_keylog}),
            sorted([log.label for log in curl_keylog]),
            "There must not be any duplicated label in curl keylog"
        )

        # Validate client randoms
        self.assertEqual(
            [log.client_random for log in siotls_keylog],
            [conn._client_nonce.hex()] * len(siotls_keylog),
            "All key logs are for the same client",
        )
        self.assertEqual(
            [log.client_random for log in curl_keylog],
            [conn._client_nonce.hex()] * len(curl_keylog),
            "All key logs are for the same client",
        )

        # Validate secret values
        siotls_keylog = {label: value for label, _, value in siotls_keylog}
        curl_keylog = {label: value for label, _, value in curl_keylog}
        for label, curl_value in curl_keylog.items():
            self.assertEqual(siotls_keylog[label], curl_value,
                "siotls and curl must compute the same secrets")

