# ruff: noqa: S603

import dataclasses
import errno
import logging
import os
import re
import shutil
import socket
import subprocess as sp
import unittest
from collections import namedtuple
from os import fspath
from threading import Thread

from siotls import TLSConnection
from siotls.iana import NamedGroup
from siotls.utils import make_http11_response

from . import TAG_INTEGRATION, TestCase
from .config import server_config, test_pem_dir, test_temp_dir

HOST = '127.0.0.2'
PORT = 8446
CURL_PATH = shutil.which('curl')

logger = logging.getLogger(__name__)
curl_logger = logger.getChild('curl')


def fix_curl_log(message):
    # might be a nice first contribution to cURL...
    return message.replace(
        "TLS header, Finished (20)", "TLS header, Change Cipher Spec (20)"
    ).replace(
        "TLS header, Unknown (21)", "TLS header, Alert (21)"
    ).replace(
        "TLS header, Certificate Status (22)", "TLS header, Handshake (22)"
    ).replace(
        "TLS header, Supplemental data (23)", "TLS header, Application Data (23)"
    )


@unittest.skipUnless(TAG_INTEGRATION, "enable with SIOTLS_INTEGRATION=1")
@unittest.skipUnless(CURL_PATH, "curl not found in path")
class TestCURL(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.socket = socket.socket()
        cls.addClassCleanup(cls.socket.close)
        cls.addClassCleanup(cls.socket.shutdown, socket.SHUT_RDWR)
        cls.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.socket.bind((HOST, PORT))
        cls.socket.listen(1)
        cls.socket.settimeout(1)

        cls.keylogfile = (test_temp_dir / 'keylogfile.txt').open('w+')
        cls.addClassCleanup(cls.keylogfile.close)

        cls.curl_pipe_r, cls.curl_pipe_w = os.pipe()
        cls.addClassCleanup(os.close, cls.curl_pipe_r)
        cls.addClassCleanup(os.close, cls.curl_pipe_w)
        Thread(target=cls.run_curl_logging, args=(curl_logger,)).start()

    @classmethod
    def run_curl_logging(cls, curl_logger):
        curl_log_re = re.compile(r'^(?:(\*)|== (\w+):) ', re.MULTILINE)
        buffer = ""
        while True:
            try:
                read = os.read(cls.curl_pipe_r, 1024).decode(errors='ignore')
            except OSError:
                break
            *messages, buffer = curl_log_re.split(buffer + read)
            for message, group1, group2 in zip(it:=iter(messages), it, it, strict=True):
                if not message:
                    continue
                level_name = 'INFO' if group1 else group2.upper()
                curl_logger.log(
                    logging._nameToLevel[level_name],
                    fix_curl_log(message.rstrip())
                )

    def setUp(self):
        # make sure no request is pending
        self.socket.settimeout(0)
        try:
            self.socket.accept()
        except OSError as exc:
            if exc.errno not in (errno.EAGAIN, errno.ECONNABORTED):
                raise
        self.socket.settimeout(1)

        self.keylogfile.seek(0)
        self.keylogfile.truncate()

    def curl(
        self,
        version='1.3',
        max_time=1,
        tls_max='1.3',
        options=None,
    ):
        args = [
            CURL_PATH, f'https://{HOST}:{PORT}',
            '--no-progress-meter',
            '--cacert', fspath(test_pem_dir.joinpath('ca-cert.pem')),
        ]

        loglevel = logger.getEffectiveLevel()
        if loglevel <= logging.DEBUG:
            args.extend(['--trace-ascii', '-'])
        elif loglevel <= logging.INFO:
            args.append('--verbose')
        elif loglevel <= logging.WARNING:
            pass
        elif loglevel <= logging.ERROR:
            args.append('--show-error')
        else:
            args.append('--silent')

        if version:
            args.append(f'--tlsv{version}')
        if max_time is not None:
            args.append('--max-time')
            args.append(str(max_time))
        if tls_max is not None:
            args.append('--tls-max')
            args.append(tls_max)
        for option, value in (options or {}).items():
            args.append(f'--{option}')
            args.append(value)
        env = {'SSLKEYLOGFILE': self.keylogfile.name}
        proc = sp.Popen(args, stdout=self.curl_pipe_w, stderr=self.curl_pipe_w, env=env)
        self.addCleanup(proc.wait, timeout=1)
        self.addCleanup(proc.terminate)

        client, client_info = self.socket.accept()
        self.addCleanup(client.close)

        return proc, client

    def test_curl_keylogfile(self):
        KeyLogFormat = namedtuple("KeyLogFormat", ["label", "client_random", "value"])

        config = dataclasses.replace(
            server_config,
            key_exchanges=[NamedGroup.ffdhe2048],
            alpn=['http/1.1'],
            log_keys=True
        )
        conn =  TLSConnection(config)
        proc, client = self.curl()

        with self.assertLogs('siotls.keylog', level='INFO') as logs:  # noqa: SIM117
            with conn.wrap(client) as sclient:
                http_get = sclient.read()
                self.assertEqual(
                    http_get.partition(b'\r\n')[0],
                    b"GET / HTTP/1.1"
                )
                sclient.write(make_http11_response(204, "").encode())

        client.close()
        proc.wait(timeout=1)

        siotls_keylog = [
            KeyLogFormat(*line.rpartition(':')[2].split(' '))
            for line in logs.output
            if '#' not in line
        ]

        curl_keylog = [
            KeyLogFormat(*line.strip().split(' '))
            for line in self.keylogfile.readlines()
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
            [conn._client_unique.hex()] * len(siotls_keylog),
            "All key logs are for the same client siotls side",
        )
        self.assertEqual(
            [log.client_random for log in curl_keylog],
            [conn._client_unique.hex()] * len(curl_keylog),
            "All key logs are for the same client curl side",
        )

        # Validate secret values
        siotls_keylog = {label: value for label, _, value in siotls_keylog}
        curl_keylog = {label: value for label, _, value in curl_keylog}
        self.assertEqual(set(siotls_keylog), set(curl_keylog))
        self.assertEqual(siotls_keylog, curl_keylog)
