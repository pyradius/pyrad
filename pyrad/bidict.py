# bidict.py
#
# Bidirectional map


class BiDict:
    def __init__(self):
        self.forward = {}
        self.backward = {}

    def add(self, one, two):
        self.forward[one] = two
        self.backward[two] = one

    def __len__(self):
        return len(self.forward)

    def __getitem__(self, key):
        return self.get_forward(key)

    def __delitem__(self, key):
        if key in self.forward:
            del self.backward[self.forward[key]]
            del self.forward[key]
        else:
            del self.forward[self.backward[key]]
            del self.backward[key]

    def get_forward(self, key):
        return self.forward[key]

    def has_forward(self, key):
        return key in self.forward

    def get_backward(self, key):
        return self.backward[key]

    def has_backward(self, key):
        return key in self.backward
