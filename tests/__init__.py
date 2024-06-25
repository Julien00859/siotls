import argparse
import atexit
import contextlib
import dataclasses
import logging
import re
import shutil
import tempfile
import unittest
from os import fspath, getenv
from pathlib import Path

from siotls.__main__ import setup_logging
from siotls.contents import Content
from siotls.serial import SerialIO

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='verbosity', action='count', default=0)
options, _ = parser.parse_known_args()

logging.basicConfig()
setup_logging(logging.ERROR - 10 * options.verbosity)

test_temp_dir = Path(tempfile.mkdtemp(prefix='siotls-test-'))
atexit.register(shutil.rmtree, fspath(test_temp_dir), ignore_errors=True)

TAG_INTEGRATION = getenv('SIOTLS_INTEGRATION') == '1'


class TestCase(unittest.TestCase):
    def assertRaises(  # noqa: N802
        self,
        exception,
        *args,
        error_msg=None,
        error_pattern=None,
        **kwds
    ):
        """
        Context manager that assert that the block raises an exception.

        :param str error_msg: assert that the exception's ``args[0]`` is
            equal to this string
        :param str error_pattern: assert that the exception's
            ``args[0]`` matches this regexp pattern
        """
        if error_msg is None:
            return super().assertRaises(exception, *args, **kwds)
        if error_msg:
            error_pattern = re.escape(error_msg)
        return self.assertRaisesRegex(exception, error_pattern, *args, **kwds)

    @contextlib.contextmanager
    def assertLogs(  # noqa: N802
        self,
        logger='',
        level=logging.NOTSET,
        *args,
        log_msg=None,
        log_pattern=None,
        **kwds
    ):
        """
        Context manager that assert that the block logs a message.

        :param str log_msg: assert that at least one of the log lines is
            equal to this string
        :param str log_pattern: assert that at least one of the log
            lines matches this regexp pattern
        """
        with super().assertLogs(logger, level, *args, **kwds) as capture:
            yield capture
        if log_msg is not None:
            log_pattern = re.escape(log_msg)
        if log_pattern is not None:
            for logline in capture.output:
                message = logline.split(':', 2)[2]
                if re.match(log_pattern, message):
                    break
            else:
                self.assertRegex(message, log_pattern)  # it fails


def tls_decode(tls_connection, new_data=None):
    contents = []
    input_data = tls_connection._input_data
    input_handshake = tls_connection._input_handshake
    try:
        if new_data:
            tls_connection._input_data += new_data
        while next_content := tls_connection._read_next_content():
            content_type, content_data = next_content
            stream = SerialIO(content_data)
            content = Content.get_parser(content_type).parse(stream)
            stream.assert_eof()
            contents.append(content)
    finally:
        tls_connection._input_data = input_data
        tls_connection._input_handshake = input_handshake
    return contents
