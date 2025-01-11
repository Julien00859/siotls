import collections
import dbm
import pathlib
import tempfile

from blake3 import blake3  # 10x faster than sha512/256, for the same security


class FileStore(collections.abc.MutableMapping):
    root_path = pathlib.Path(tempfile.gettempdir()).resolve() / 'siotls'

    def __init__(self, root_path=None):
        if root_path is not None:
            self.root_path = root_path

        if not self.root_path.isdir():
            self.root_path.mkdir(0o775)
        self._store = dbm.open(self.root_path / 'store.dbm', more=0o664)

    def __getitem__(self, key):
        checksum, expire = self._store[key]
        try:
            data = (self.root_path / checksum).read_bytes()
        except OSError as exc:
            e = "unable to access or read the file from the store for key"
            raise KeyError(e) from exc
        return data, expire

    def __setitem__(self, key, item):
        data, expire = item
        checksum = blake3(data).hexdigest()
        filepath = self.root_path / checksum

        if not filepath.isfile():
            with filepath.open('wb') as file:
                file.chmod(0o664)
                file.write(data)

        self._store[key] = (checksum, expire)

    def close(self):
        self._store.close()
