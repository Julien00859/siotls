from siotls.serial import MissingDataError, SerialIO, TLSBufferError, TooMuchDataError

from . import TestCase


class TestSerial(TestCase):
    def test_serial_init_empty(self):
        stream = SerialIO()
        self.assertEqual(stream.getvalue(), b"")
        self.assertEqual(stream.tell(), 0)
        self.assertTrue(stream.is_eof())
        stream.assert_eof()
        self.assertEqual(stream.read(), b"")
        stream.assert_eof()

    def test_serial_init_full(self):
        stream = SerialIO(b"some data")
        self.assertEqual(stream.getvalue(), b"some data")
        self.assertEqual(stream.tell(), 0)
        self.assertFalse(stream.is_eof())
        self.assertRaises(TooMuchDataError, stream.assert_eof)
        self.assertEqual(stream.read(), b"some data")
        stream.assert_eof()

    def test_serial_read_exactly(self):
        stream = SerialIO(b"some data")
        self.assertEqual(stream.read_exactly(0), b"")
        self.assertEqual(stream.read_exactly(3), b"som")
        self.assertFalse(stream.is_eof())
        self.assertEqual(stream.read_exactly(3), b"e d")
        self.assertFalse(stream.is_eof())
        self.assertRaises(MissingDataError, stream.read_exactly, 4)
        self.assertTrue(stream.is_eof())

    def test_serial_read_int(self):
        self.assertEqual(SerialIO(b"\x00ab").read_int(1), 0)
        self.assertEqual(SerialIO(b"\x01\x00ab").read_int(2), 256)
        self.assertRaises(ValueError, SerialIO(b"\x00").read_int, 0)
        self.assertRaises(MissingDataError, SerialIO().read_int, 1)
        self.assertRaises(MissingDataError, SerialIO(b"\x00").read_int, 2)

    def test_serial_write_int(self):
        stream = SerialIO()
        stream.write_int(1, 0)
        self.assertEqual(stream.getvalue(), b"\x00")
        self.assertEqual(stream.tell(), 1)
        self.assertTrue(stream.is_eof())

        stream = SerialIO()
        stream.write_int(2, 0)
        self.assertEqual(stream.getvalue(), b"\x00\x00")
        self.assertEqual(stream.tell(), 2)
        self.assertTrue(stream.is_eof())

        stream = SerialIO()
        self.assertRaises(OverflowError, stream.write_int, 1, 256)
        self.assertEqual(stream.tell(), 0)
        self.assertTrue(stream.is_eof())

        stream = SerialIO()
        stream.write_int(2, 256)
        self.assertEqual(stream.getvalue(), b"\x01\x00")
        self.assertEqual(stream.tell(), 2)
        self.assertTrue(stream.is_eof())

    def test_serial_read_var(self):
        self.assertEqual(SerialIO(b"\x00").read_var(1), b"")
        self.assertRaises(MissingDataError, SerialIO(b"").read_var, 1)
        self.assertEqual(SerialIO(b"\x01\x00ab").read_var(1), b"\x00")
        self.assertRaises(MissingDataError, SerialIO(b"\x01").read_var, 1)

        stream = SerialIO(b"\x05123456")
        self.assertEqual(stream.read_var(1), b"12345")
        self.assertEqual(stream.tell(), 6)
        self.assertEqual(stream.read(), b"6")

    def test_serial_write_var(self):
        stream = SerialIO()
        stream.write_var(1, b"hello")
        self.assertEqual(stream.getvalue(), b"\x05hello")

        stream = SerialIO()
        self.assertRaises(OverflowError, stream.write_var, 0, b"hello")

        stream = SerialIO()
        stream.write_var(2, b"hello")
        self.assertEqual(stream.getvalue(), b"\x00\x05hello")

        stream = SerialIO()
        stream.write_var(2, b"hello")
        self.assertRaises(OverflowError, stream.write_var, 1, b" " * 256)

    def test_serial_read_listint(self):
        self.assertRaises(MissingDataError, SerialIO().read_listint, 1, 1)
        self.assertEqual(SerialIO(b"\x01\x00").read_listint(1, 1), [0])
        self.assertEqual(SerialIO(b"\x03\x00\x02\x01").read_listint(1, 1), [0, 2, 1])
        self.assertRaises(MissingDataError, SerialIO(b"\x03\x00\x02").read_listint, 1, 1)
        self.assertEqual(SerialIO(b"\x04\x00\x02\x01\x01").read_listint(1, 2), [2, 257])
        self.assertRaises(TLSBufferError, SerialIO(b"\x01\x00").read_listint, 1, 2)
        self.assertEqual(SerialIO(b"\x00\x04\x00\x02\x01\x01").read_listint(2, 1), [0, 2, 1, 1])
        self.assertEqual(SerialIO(b"\x00\x04\x00\x02\x01\x01").read_listint(2, 2), [2, 257])

    def test_serial_write_listint(self):
        stream = SerialIO()
        stream.write_listint(1, 1, [0, 2, 1])
        self.assertEqual(stream.getvalue(), b"\x03\x00\x02\x01")

        stream = SerialIO()
        stream.write_listint(2, 1, [0, 2, 1])
        self.assertEqual(stream.getvalue(), b"\x00\x03\x00\x02\x01")

        stream = SerialIO()
        self.assertRaises(OverflowError, stream.write_listint, 1, 1, [256])
        self.assertRaises(OverflowError, stream.write_listint, 1, 1, [0] * 256)

        stream = SerialIO()
        stream.write_listint(1, 2, [2, 257])
        self.assertEqual(stream.getvalue(), b"\x04\x00\x02\x01\x01")

        stream = SerialIO()
        stream.write_listint(2, 2, [2, 257])
        self.assertEqual(stream.getvalue(), b"\x00\x04\x00\x02\x01\x01")

    def test_serial_read_listvar(self):
        self.assertRaises(MissingDataError, SerialIO().read_listvar, 1, 1)
        self.assertEqual(SerialIO(b"\x01\x00").read_listvar(1, 1), [b""])
        self.assertEqual(SerialIO(b"\x05\x00\x01a\x01a").read_listvar(1, 1), [b"", b"a", b"a"])
        self.assertRaises(MissingDataError, SerialIO(b"\x03\x00\x02").read_listvar, 1, 1)
        self.assertRaises(MissingDataError, SerialIO(b"\x02\x00\x02").read_listvar, 1, 1)
        self.assertEqual(SerialIO(b"\x00\x04\x00\x02ab").read_listvar(2, 1), [b"", b"ab"])
        self.assertEqual(SerialIO(b"\x00\x04\x00\x02ab").read_listvar(2, 2), [b"ab"])

    def test_serial_write_listvar(self):
        stream = SerialIO()
        stream.write_listvar(1, 1, [b""])
        self.assertEqual(stream.getvalue(), b"\x01\x00")

        stream = SerialIO()
        stream.write_listvar(1, 1, [b"", b"ab", b"a"])
        self.assertEqual(stream.getvalue(), b"\x06\x00\x02ab\x01a")

        stream = SerialIO()
        self.assertRaises(OverflowError, stream.write_listvar, 1, 1, [b" " * 256])
        self.assertRaises(OverflowError, stream.write_listvar, 1, 1, [b" "] * 256)

        stream = SerialIO()
        stream.write_listvar(2, 1, [b"", b"ab"])
        self.assertEqual(stream.getvalue(), b"\x00\x04\x00\x02ab")

        stream = SerialIO()
        stream.write_listvar(2, 2, [b"", b"ab"])
        self.assertEqual(stream.getvalue(), b"\x00\x06\x00\x00\x00\x02ab")

    def test_serial_limit(self):
        stream = SerialIO(b"\x02\x01\x01\x01some data")
        with stream.limit(3):
            with stream.lookahead():
                self.assertEqual(stream.read(3), b"\x02\x01\x01")
                self.assertRaises(TooMuchDataError, stream.read, 1)
            with stream.lookahead():
                self.assertEqual(stream.read_exactly(3), b"\x02\x01\x01")
                self.assertRaises(TooMuchDataError, stream.read_exactly, 1)
            with stream.lookahead():
                self.assertEqual(stream.read_int(3), 2*256**2 + 1*256 + 1)
                self.assertRaises(TooMuchDataError, stream.read_int, 1)
            with stream.lookahead():
                self.assertEqual(stream.read_var(1), b"\x01\x01")
                self.assertRaises(TooMuchDataError, stream.read_var, 1)
            with stream.lookahead():
                self.assertEqual(stream.read_listint(1, 1), [1, 1])
                self.assertRaises(TooMuchDataError, stream.read_listint, 1, 1)
            with stream.lookahead():
                self.assertEqual(stream.read_listvar(1, 1), [b"\x01"])
                self.assertRaises(TooMuchDataError, stream.read_listvar, 1, 1)
            self.assertEqual(stream.read(), b"\x02\x01\x01")

        stream = SerialIO(b"some data")
        with stream.limit(4):
            e = "a more restrictive limit is present already"
            with self.assertRaises(ValueError, error_msg=e):  # noqa: SIM117
                with stream.limit(5):
                    pass
            stream.read(1)
            with self.assertRaises(ValueError, error_msg=e):  # noqa: SIM117
                with stream.limit(4):
                    pass

            with stream.limit(1):
                stream.read(1)

            e = "expected end of chunk but 1 bytes remain"
            with self.assertRaises(TooMuchDataError, error_msg=e):  # noqa: SIM117
                with stream.limit(2):
                    stream.read(1)
            stream.read()

    def test_serial_lookahead(self):
        stream = SerialIO(b"some data")
        self.assertEqual(stream.tell(), 0)
        with stream.lookahead():
            self.assertEqual(stream.read(3), b"som")
            self.assertEqual(stream.tell(), 3)
            with stream.lookahead():
                self.assertEqual(stream.read(3), b"e d")
                self.assertEqual(stream.tell(), 6)
            self.assertEqual(stream.tell(), 3)
            self.assertEqual(stream.read(3), b"e d")
        self.assertEqual(stream.tell(), 0)
        self.assertEqual(stream.read(3), b"som")
