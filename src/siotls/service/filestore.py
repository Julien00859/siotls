import collections
import dbm
import pathlib
import struct
import tempfile
from datetime import UTC, datetime

from blake3 import blake3  # 10x faster than sha512/256, for the same security

struct_formats = {
    0: f"<B{blake3.digest_size}sf"
}


class FileStore(collections.abc.MutableMapping):
    root_path = pathlib.Path(tempfile.gettempdir()).resolve() / 'siotls'

    def __init__(self, root_path=None):
        if root_path is not None:
            self.root_path = root_path
        if not self.root_path.isdir():
            self.root_path.mkdir(0o775)
        self._store = dbm.open(self.root_path / 'store.dbm', mode=0o664)  # noqa: SIM115

    def _parse(self, key, entry):
        version = int.from_bytes(entry[0], 'little')
        try:
            return struct_formats[version].unpack(entry)
        except (KeyError, ValueError) as exc:
            raise KeyError(key) from exc

    def __getitem__(self, key):
        match self._parse(key, self._store[key]):
            case (0, checksum, expire_timestamp):
                filepath = self.root_path / checksum.hex()
                try:
                    data = filepath.read_bytes()
                except OSError as exc:
                    exc_ = KeyError(key)
                    exc_.add_note(f"unable to access or read the file at {filepath}")
                    raise exc_ from exc

                return data, datetime.fromtimestamp(expire_timestamp, UTC)

    def __setitem__(self, key, item):
        data, expire = item

        # using the checkum as filename has two advantages: (1) it makes
        # sure there are no weird chacaters, (2) it makes so a same file
        # with different keys is only stored once.
        checksum = blake3(data).digest()
        filepath = self.root_path / checksum.hex()
        if not filepath.isfile():
            with filepath.open('wb') as file:
                file.chmod(0o664)
                file.write(data)

        version = 0
        self._store[key] = struct.pack(
            struct_formats[version],
            (version, checksum, expire.timestamp())
        )

    def __delitem__(self, key):
        entry = self._store.pop(key)
        match self._parse(key, entry):
            case (0, checksum, _):
                (self.root_path / checksum.hex()).unlink()

    def close(self):
        self._store.close()
