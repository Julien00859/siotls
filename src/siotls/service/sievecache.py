import collections
import collections.abc
import inspect

# Get the pure python implementation of collections.OrderedDict
try:
    _collections_globals = {k: getattr(collections, k) for k in dir(collections)}
    exec(inspect.getsource(collections.OrderedDict), _collections_globals)  # noqa: S102
    PyOrderedDict = _collections_globals.pop("OrderedDict")
    del _collections_globals
except OSError:
    PyOrderedDict = dict


class _CacheEntry:
    def __init__(self, item):
        self.item = item
        self.visited = False

    def __repr__(self):
        return repr((self.item, self.visited))


class SieveCache(collections.abc.MutableMapping):
    # Sieve, the eviction algorithm that is simpler than LRU
    # https://www.usenix.org/system/files/nsdi24-zhang-yazhuo.pdf
    maxlen = 64

    def __init__(self, maxlen=None):
        if maxlen is not None:
            if maxlen < 1:
                e = f"maxlen must be None or a positive integer: {maxlen}"
                raise ValueError(e)
            self.maxlen = maxlen
        self._entries = PyOrderedDict()
        self._entries_map = self._entries._OrderedDict__map  # noqa: SLF001
        self._entries_root = self._entries._OrderedDict__root  # noqa: SLF001
        self._hand = None

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self._entries)

    def __getitem__(self, key):
        entry = self._entries[key]
        entry.visited = True
        return entry.item

    def __setitem__(self, key, item):
        entry = _CacheEntry(item)
        if len(self._entries) == self.maxlen:
            self.popitem()
        self._entries[key] = entry  # it inserts at the tail

    def __delitem__(self, key):
        del self._entries[key]

    def popitem(self):
        if not self._entries:
            e = "popitem from an empty cache"
            raise KeyError(e)

        hand = self._hand or self._entries_root.next  # head
        for _ in range(len(self._entries)):  # safeguard
            try:
                entry = self._entries[hand.key]
            except AttributeError:
                hand = self._entries_root.next
                break
            if not entry.visited:
                break
            entry.visited = False
            hand = hand.next

        self._hand = hand.next
        return (hand.key, self._entries.pop(hand.key))

    def keys(self):
        return self._entries.keys()

    def items(self):
        return ((key, entry.item) for key, entry in self._entries.items())

    def values(self):
        return (entry.item for entry in self._entries.values())

    def __repr__(self):
        name = type(self).__name__
        items = dict(self.items())
        return f"{name}({items})"
