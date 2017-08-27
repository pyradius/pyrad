# bidict.py
#
# Bidirectional map


class BiDict(object):
  """Create a bi-directional map object."""

  def __init__(self):
    self.forward = {}
    self.backward = {}

  def add(self, one, two):
    """Adds two elements to the forward and backward dicts."""
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
    """Get the key from the forward dict and return it."""
    return self.forward[key]

  def has_forward(self, key):
    """Determines if the key is in the forward dict."""
    return key in self.forward

  def get_backward(self, key):
    """Get the key from the backward dict and return it."""
    return self.backward[key]

  def has_backward(self, key):
    """Determines if the key is in the backward dict."""
    return key in self.backward
