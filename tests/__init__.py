import argparse
import contextlib
import logging
import re
import unittest

from siotls.__main__ import setup_logging

parser = argparse.ArgumentParser()
parser.add_argument('-v', dest='verbosity', action='count', default=0)
options, _ = parser.parse_known_args()

logging.basicConfig()
setup_logging(logging.WARNING - 10 * options.verbosity)


class TestCase(unittest.TestCase):
    def assertRaises(self, exception, *args, error_msg=None, **kwds):  # noqa: N802
        if error_msg is None:
            return super().assertRaises(exception, *args, **kwds)
        return self.assertRaisesRegex(exception, re.escape(str(error_msg)), *args, **kwds)

    @contextlib.contextmanager
    def assertLogs(self, logger='', level=logging.NOTSET, log_msg=None, *args, **kwds):  # noqa: N802
        with super().assertLogs(logger, level, *args, **kwds) as capture:
            yield capture
        if log_msg is not None:
            self.assertEqual(len(capture.output), 1)
            self.assertRegex(capture.output[0].split(':', 2)[2], re.escape(str(log_msg)))
