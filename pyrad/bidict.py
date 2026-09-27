# bidict.py
#
# Bidirectional map


class BiDict:
    def __init__(self):
        self.forward = {}
        self.backward = {}

    def Add(self, one, two):
        """Map one to two and two to one. Several keys may map to the same
        value (aliases), the value then maps back to the key added last.
        Re-adding a key with another value removes its old reverse entry.
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
        return self.forward[key]

    def HasForward(self, key):
        return key in self.forward

    def GetBackward(self, key):
        return self.backward[key]

    def HasBackward(self, key):
        return key in self.backward
