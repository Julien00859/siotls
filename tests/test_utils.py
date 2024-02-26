import doctest

import siotls.utils
from siotls.utils import hexdump

from . import TestCase


class TestUtils(TestCase):
    def test_doctest(self):
        failure_count, test_count = doctest.testmod(siotls.utils)
        self.assertEqual(failure_count, 0)
        self.assertGreater(test_count, 0)

    def test_hexdump(self):
        self.assertEqual(hexdump(b""), "")

        self.assertEqual(hexdump(b"a"),
            "0000: 61                                                a")

        self.assertEqual(hexdump(b"abcdefghi"),
            "0000: 61 62 63 64 65 66 67 68  69                       abcdefgh i")

        self.assertEqual(hexdump(b"abcdefghijklmnopq"),
            "0000: 61 62 63 64 65 66 67 68  69 6a 6b 6c 6d 6e 6f 70  abcdefgh ijklmnop\n"
            "0010: 71                                                q")

        self.assertEqual(hexdump(bytes(range(16))),
            "0000: 00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f  01234567 8   c ef")

        self.assertEqual(hexdump(bytes(range(16, 32))),
            "0000: 10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  ........ ........")
