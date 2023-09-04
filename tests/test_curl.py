import errno
import shutil
import socket
import subprocess as sp
import unittest
from siotls.connection import TLSConnection

HOST = '127.0.0.2'
PORT = 8446
CURL_PATH = None#shutil.which('curl')


def curl(
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
    env = {'SSLKEYLOGFILE': '/home/julien/.tlskeylogfile'}
    return sp.run(args, env=env)


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

    def setUp(self):
        # make sure no request is pending
        self.socket.settimeout(0)
        try:
            self.socket.accept()
        except socket.error as exc:
            if exc.errno not in (errno.EAGAIN, errno.ECONNABORTED):
                raise
        self.socket.settimeout(1)

    def test_truc(self):
        conn = TLSConnection(config=None)
        curl()
        client, client_info = self.socket.accept()

        data = client.recv(256)
        print(len(data))
        client.close()
        records = conn.receive_data(data)
