from typing import Hashable


class BiDict:
    def __init__(self):
        self.forward = {}
        self.backward = {}

    def Add(self, one: Hashable, two: Hashable):
        self.forward[one] = two
        self.backward[two] = one

    def __len__(self) -> int:
        return len(self.forward)

    def __getitem__(self, key: Hashable):
        return self.GetForward(key)

    def __delitem__(self, key: Hashable):
        if key in self.forward:
            del self.backward[self.forward[key]]
            del self.forward[key]
        else:
            del self.forward[self.backward[key]]
            del self.backward[key]

    def GetForward(self, key: Hashable):
        return self.forward[key]

    def HasForward(self, key: Hashable) -> bool:
        return key in self.forward

    def GetBackward(self, key: Hashable):
        return self.backward[key]

    def HasBackward(self, key: Hashable) -> bool:
        return key in self.backward
