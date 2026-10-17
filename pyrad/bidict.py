# bidict.py
#
# Bidirectional map


class BiDict:
    """A bidirectional mapping of keys to values and values to keys.

    Used by :class:`pyrad.dictionary.Dictionary` and
    :class:`pyrad.dictionary.Attribute`. ``bidict[key]`` is
    :meth:`GetForward`, ``len(bidict)`` the number of keys, and
    ``del bidict[key]`` removes a key or, if it isn't a key, a value and
    all keys mapping to it.

    :ivar forward: the mapping of keys to values
    :vartype forward: dict
    :ivar backward: the mapping of values to keys
    :vartype backward: dict
    """

    def __init__(self):
        self.forward = {}
        self.backward = {}

    def Add(self, one, two):
        """Map the key one to the value two and two back to one.

        Several keys may map to the same value (aliases), the value then
        maps back to the key added last. Re-adding a key with another value
        removes its old reverse entry.
        """
        if one in self.forward and self.forward[one] != two:
            self.__DropBackward(one)
        self.forward[one] = two
        self.backward[two] = one

    def __DropBackward(self, one):
        """Remove the reverse entry of the value of one if it maps back to
        one, or let it map back to another key with the same value.
        """
        two = self.forward[one]
        if two not in self.backward or self.backward[two] != one:
            return
        del self.backward[two]
        for key in reversed(self.forward):
            if key != one and self.forward[key] == two:
                self.backward[two] = key
                break

    def __len__(self):
        return len(self.forward)

    def __getitem__(self, key):
        return self.GetForward(key)

    def __delitem__(self, key):
        if key in self.forward:
            self.__DropBackward(key)
            del self.forward[key]
        else:
            del self.backward[key]
            # remove all keys mapping to the deleted value
            for one in [k for (k, v) in self.forward.items() if v == key]:
                del self.forward[one]

    def GetForward(self, key):
        """Return the value of a key; raises :exc:`KeyError` if missing."""
        return self.forward[key]

    def HasForward(self, key):
        """Return whether key is a key."""
        return key in self.forward

    def GetBackward(self, key):
        """Return the key of a value; raises :exc:`KeyError` if missing."""
        return self.backward[key]

    def HasBackward(self, key):
        """Return whether key is a value."""
        return key in self.backward
