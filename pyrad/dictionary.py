# dictionary.py
#
# Copyright 2002,2005,2007,2016 Wichert Akkerman <wichert@wiggy.net>
"""
RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute
definitions from one or more dictionary files.

Dictionary files are textfiles with one command per line.
Comments are specified by starting with a # character, and empty
lines are ignored.

The commands supported are::

  ATTRIBUTE <attribute> <code> <type> [<vendor>]
  specify an attribute and its type

  VALUE <attribute> <valuename> <value>
  specify a value attribute

  VENDOR <name> <id>
  specify a vendor ID

  BEGIN-VENDOR <vendorname>
  begin definition of vendor attributes

  END-VENDOR <vendorname>
  end definition of vendor attributes


The datatypes currently supported are:

+---------------+----------------------------------------------+
| type          | description                                  |
+===============+==============================================+
| string        | ASCII string                                 |
+---------------+----------------------------------------------+
| ipaddr        | IPv4 address                                 |
+---------------+----------------------------------------------+
| date          | 32 bits UNIX                                 |
+---------------+----------------------------------------------+
| octets        | arbitrary binary data                        |
+---------------+----------------------------------------------+
| abinary       | ascend binary data                           |
+---------------+----------------------------------------------+
| ipv6addr      | 16 octets in network byte order              |
+---------------+----------------------------------------------+
| ipv6prefix    | 18 octets in network byte order              |
+---------------+----------------------------------------------+
| integer       | 32 bits unsigned number                      |
+---------------+----------------------------------------------+
| signed        | 32 bits signed number                        |
+---------------+----------------------------------------------+
| short         | 16 bits unsigned number                      |
+---------------+----------------------------------------------+
| byte          | 8 bits unsigned number                       |
+---------------+----------------------------------------------+
| tlv           | Nested tag-length-value                      |
+---------------+----------------------------------------------+
| integer64     | 64 bits unsigned number                      |
+---------------+----------------------------------------------+

These datatypes are parsed but not supported:

+---------------+----------------------------------------------+
| type          | description                                  |
+===============+==============================================+
| ifid          | 8 octets in network byte order               |
+---------------+----------------------------------------------+
| ether         | 6 octets of hh:hh:hh:hh:hh:hh                |
|               | where 'h' is hex digits, upper or lowercase. |
+---------------+----------------------------------------------+
"""
from pyrad import bidict
from pyrad import dictfile
from copy import copy

from pyrad.datatypes import leaf, structural

__docformat__ = 'epytext en'

from pyrad.datatypes.structural import AbstractStructural

DATATYPES = {
    #  leaf attributes
    'abinary': leaf.AscendBinary(),
    'byte': leaf.Byte(),
    'date': leaf.Date(),
    'ether': leaf.Ether(),
    'ifid': leaf.Ifid(),
    'integer': leaf.Integer(),
    'integer64': leaf.Integer64(),
    'ipaddr': leaf.Ipaddr(),
    'ipv6addr': leaf.Ipv6addr(),
    'ipv6prefix': leaf.Ipv6prefix(),
    'octets': leaf.Octets(),
    'short': leaf.Short(),
    'signed': leaf.Signed(),
    'string': leaf.String(),

    #  structural attributes
    'tlv': structural.Tlv(),
    'vsa': structural.Vsa()
}

class ParseError(Exception):
    """Dictionary parser exceptions.

    :ivar msg:        Error message
    :type msg:        string
    :ivar linenumber: Line number on which the error occurred
    :type linenumber: integer
    """

    def __init__(self, msg=None, **data):
        self.msg = msg
        self.file = data.get('file', '')
        self.line = data.get('line', -1)

    def __str__(self):
        str = ''
        if self.file:
            str += self.file
        if self.line > -1:
            str += '(%d)' % self.line
        if self.file or self.line > -1:
            str += ': '
        str += 'Parse error'
        if self.msg:
            str += ': %s' % self.msg

        return str

class Attribute(object):
    """
    class to represent an attribute as defined by the radius dictionaries
    """
    def __init__(self, name, number, datatype, parent=None, vendor=None,
                 values=None, encrypt=0, tags=None):
        if datatype not in DATATYPES:
            raise ValueError('Invalid data type')
        self.name = name
        self.number = number
        # store a datatype object as the Attribute type
        self.type = DATATYPES[datatype]
        # parent is used to denote TLV parents, this does not include vendors
        self.parent = parent
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = tags

        # values as specified in the dictionary
        self.values = bidict.BiDict()
        if values:
            for key, value in values.items():
                self.values.Add(key, value)

        self.children = {}
        # bidirectional mapping of children name <-> numbers for the namespace
        # defined by this attribute
        self.attrindex = bidict.BiDict()

    def encode(self, decoded: any, *args, **kwargs) -> bytes:
        """
        encodes value with attribute datatype
        @param decoded: value to encode
        @type decoded: any
        @param args:
        @param kwargs:
        @return: encoding of object
        @rtype: bytes
        """
        return self.type.encode(self, decoded, args, kwargs)

    def decode(self, raw: bytes|dict) -> any:
        """
        decodes bytestring or dictionary with attribute datatype

        raw can either be a bytestring (for leaf attributes) or a dictionary (
        for TLVs)
        @param raw: value to decode
        @type raw: bytes | dict
        @return: python data structure
        @rtype: any
        """
        #  Use datatype.decode to decode leaf attributes
        if isinstance(raw, bytes):
            # precautionary check to see if the raw data is truly being held
            # by a leaf attribute
            if isinstance(self.type, AbstractStructural):
                raise ValueError('Structural datatype holding string!')
            return self.type.decode(raw)

        #  Recursively calls sub attribute's .decode() until a leaf attribute
        #  is reached
        for sub_attr, value in raw.items():
            raw[sub_attr] = self.children[sub_attr].decode(value)
        return raw

    def get_value(self, packet: bytes, offset: int) -> (tuple[((int, ...), bytes | dict), ...], int):
        """
        gets encapsulated value from attribute
        @type: dictionary: Dictionary
        @type: code: tuple of ints
        @param packet: packet in bytestring
        @type: packet: bytes
        @param offset: cursor where current attribute starts in packet
        @type: offset: int
        @return: encapsulated value, bytes read
        @rtype: any, int
        """
        return self.type.get_value(self, packet, offset)

    def __getitem__(self, key):
        if isinstance(key, int):
            if not self.attrindex.HasBackward(key):
                raise KeyError(f'Missing attribute {key}')
            key = self.attrindex.GetBackward(key)
        if key not in self.children:
            raise KeyError(f'Non-existent sub attribute {key}')
        return self.children[key]

    def __setitem__(self, key: str, value: 'Attribute'):
        if key != value.name:
            raise ValueError('Key must be equal to Attribute name')
        self.children[key] = value
        self.attrindex.Add(key, value.number)

class AttrStack:
    """
    class representing the nested layers of attributes in dictionaries
    """
    def __init__(self):
        self.attributes = []
        self.namespaces = []

    def push(self, attr: Attribute, namespace: bidict.BiDict) -> None:
        """
        Pushes an attribute and a namespace onto the stack

        Currently, the namespace will always be the namespace of the attribute
        that is passed in. However, for future considerations (i.e., the group
        datatype), we have somewhat redundant code here.
        @param attr: attribute to add children to
        @param namespace: namespace defining
        @return: None
        """
        self.attributes.append(attr)
        self.namespaces.append(namespace)

    def pop(self) -> None:
        """
        removes the top most layer
        @return: None
        """
        del self.attributes[-1]
        del self.namespaces[-1]

    def top_attr(self) -> Attribute:
        """
        gets the top most attribute
        @return: attribute
        """
        return self.attributes[-1]

    def top_namespace(self) -> bidict.BiDict:
        """
        gets the top most namespace
        @return: namespace
        """
        return self.namespaces[-1]

class Vendor:
    """
    class representing a vendor with its attributes

    the existence of this class allows us to have a namespace for vendor
    attributes. if vendor was only represented by an int or string in the
    Vendor-Specific attribute (i.e., Vendor-Specific = { 16 = [ foo ] }), it is
    difficult to have a nice namespace mapping of vendor attribute names to
    numbers.
    """
    def __init__(self, name: str, number: int):
        """

        @param name: name of the vendor
        @param number: vendor ID
        """
        self.name = name
        self.number = number

        self.attributes = {}
        self.attrindex = bidict.BiDict()

    def __getitem__(self, key: str|int) -> Attribute:
        # if using attribute number, first convert to attribute name
        if isinstance(key, int):
            if not self.attrindex.HasBackward(key):
                raise KeyError(f'Non existent attribute {key}')
            key = self.attrindex.GetBackward(key)

        # return the attribute by name
        return self.attributes[key]

    def __setitem__(self, key: str, value: Attribute):
        # key must be the attribute's name
        if key != value.name:
            raise ValueError('Key must be equal to Attribute name')

        # update both the attribute and index dicts
        self.attributes[key] = value
        self.attrindex.Add(value.name, value.number)

class Dictionary(object):
    """RADIUS dictionary class.
    This class stores all information about vendors, attributes and their
    values as defined in RADIUS dictionary files.

    :ivar vendors:    bidict mapping vendor name to vendor code
    :type vendors:    bidict
    :ivar attrindex:  bidict mapping
    :type attrindex:  bidict
    :ivar attributes: bidict mapping attribute name to attribute class
    :type attributes: bidict
    """

    def __init__(self, dict=None, *dicts):
        """
        :param dict:  path of dictionary file or file-like object to read
        :type dict:   string or file
        :param dicts: list of dictionaries
        :type dicts:  sequence of strings or files
        """
        self.vendors = bidict.BiDict()
        self.vendors.Add('', 0)
        self.attrindex = bidict.BiDict()
        self.attributes = {}
        self.defer_parse = []

        self.stack = AttrStack()
        # the global attribute namespace is the first layer
        self.stack.push(self.attributes, self.attrindex)

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self):
        return len(self.attributes)

    def __getitem__(self, key):
        # allow indexing attributes by number (instead of name).
        # since the key must be an int, this still allows attribute names like
        # "1", "2", etc. (which are stored as strings)
        if isinstance(key, int):
            # check to see if attribute exists
            if not self.attrindex.HasBackward(key):
                raise KeyError(f'Attribute number {key} not defined')
            # gets attribute name from number using index
            key = self.attrindex.GetBackward(key)
        return self.attributes[key]

    def __contains__(self, key):
        # allow checks using attribute number
        if isinstance(key, int):
            return self.attrindex.HasBackward(key)
        return key in self.attributes

    has_key = __contains__

    def __ParseAttribute(self, state, tokens):
        if not len(tokens) in [4, 5]:
            raise ParseError(
                'Incorrect number of tokens for attribute definition',
                name=state['file'],
                line=state['line'])

        vendor = state['vendor']
        inline_vendor = False
        has_tag = False
        encrypt = 0
        if len(tokens) >= 5:
            def keyval(o):
                kv = o.split('=')
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)
            options = [keyval(o) for o in tokens[4].split(',')]
            for (key, val) in options:
                if key == 'has_tag':
                    has_tag = True
                elif key == 'encrypt':
                    if val not in ['1', '2', '3']:
                        raise ParseError(
                                'Illegal attribute encryption: %s' % val,
                                file=state['file'],
                                line=state['line'])
                    encrypt = int(val)

            if (not has_tag) and encrypt == 0:
                vendor = tokens[4]
                inline_vendor = True
                if not self.vendors.HasForward(vendor):
                    if vendor == "concat":
                        # ignore attributes with concat (freeradius compat.)
                        return None
                    else:
                        raise ParseError('Unknown vendor ' + vendor,
                                         file=state['file'],
                                         line=state['line'])

        (name, code, datatype) = tokens[1:4]

        codes = code.split('.')

        # Codes can be sent as hex, or octal or decimal string representations.
        tmp = []
        for c in codes:
          if c.startswith('0x'):
            tmp.append(int(c, 16))
          elif c.startswith('0o'):
            tmp.append(int(c, 8))
          else:
            tmp.append(int(c, 10))
        codes = tmp

        if len(codes) == 2:
            code = int(codes[1])
            parent = self.stack.top_attr()[self.stack.top_namespace().GetBackward(int(codes[0]))]

            # currently, the presence of a parent attribute means that we are
            # dealing with a TLV, so push the TLV layer onto the stack
            self.stack.push(parent, parent.attrindex)
        elif len(codes) == 1:
            code = int(codes[0])
            parent = None
        else:
            raise ParseError('nested tlvs are not supported')

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'])

        attribute = Attribute(name, code, datatype, parent, vendor,
                              encrypt=encrypt, tags=has_tag)

        # if detected an inline vendor (vendor in the flags field), set the
        # attribute under the vendor's attributes
        # THIS FUNCTION IS NOT SUPPORTED IN FRv4 AND SUPPORT WILL BE REMOVED
        if inline_vendor:
            self.attributes['Vendor-Specific'][vendor][name] = attribute
        else:
            # add attribute name and number mapping to current namespace
            self.stack.top_namespace().Add(name, code)
            # add attribute to current namespace
            self.stack.top_attr()[name] = attribute
            if parent:
                # add attribute to parent
                parent[name] = attribute
                # must remove the TLV layer when we are done with it
                self.stack.pop()

    def __ParseValue(self, state, tokens, defer):
        if len(tokens) != 4:
            raise ParseError('Incorrect number of tokens for value definition',
                             file=state['file'],
                             line=state['line'])

        (attr, key, value) = tokens[1:]

        try:
            adef = self.stack.top_attr()[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            raise ParseError('Value defined for unknown attribute ' + attr,
                             file=state['file'],
                             line=state['line'])

        if adef.type in ['integer', 'signed', 'short', 'byte', 'integer64']:
            value = int(value, 0)
        value = adef.encode(value)
        self.stack.top_attr()[attr].values.Add(key, value)

    def __ParseVendor(self, state, tokens):
        if len(tokens) not in [3, 4]:
            raise ParseError(
                    'Incorrect number of tokens for vendor definition',
                    file=state['file'],
                    line=state['line'])

        # Parse format specification, but do
        # nothing about it for now
        if len(tokens) == 4:
            fmt = tokens[3].split('=')
            if fmt[0] != 'format':
                raise ParseError(
                        "Unknown option '%s' for vendor definition" % (fmt[0]),
                        file=state['file'],
                        line=state['line'])
            try:
                (t, l) = tuple(int(a) for a in fmt[1].split(','))
                if t not in [1, 2, 4] or l not in [0, 1, 2]:
                    raise ParseError(
                        'Unknown vendor format specification %s' % (fmt[1]),
                        file=state['file'],
                        line=state['line'])
            except ValueError:
                raise ParseError(
                        'Syntax error in vendor specification',
                        file=state['file'],
                        line=state['line'])

        (name, number) = tokens[1:3]
        self.vendors.Add(name, int(number, 0))
        self.attributes['Vendor-Specific'][name] = Vendor(name, int(number))

    def __ParseBeginVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                    'Incorrect number of tokens for begin-vendor statement',
                    file=state['file'],
                    line=state['line'])

        name = tokens[1]

        if not self.vendors.HasForward(name):
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % name,
                    file=state['file'],
                    line=state['line'])

        state['vendor'] = name

        vendor = self.attributes['Vendor-Specific'][name]
        self.stack.push(vendor, vendor.attrindex)

    def __ParseEndVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                'Incorrect number of tokens for end-vendor statement',
                file=state['file'],
                line=state['line'])

        vendor = tokens[1]

        if state['vendor'] != vendor:
            raise ParseError(
                    'Ending non-open vendor' + vendor,
                    file=state['file'],
                    line=state['line'])
        state['vendor'] = ''
        # remove the vendor layer
        self.stack.pop()

    def ReadDictionary(self, file):
        """Parse a dictionary file.
        Reads a RADIUS dictionary file and merges its contents into the
        class instance.

        :param file: Name of dictionary file to parse or a file-like object
        :type file:  string or file-like object
        """

        fil = dictfile.DictFile(file)

        state = {}
        state['vendor'] = ''
        state['tlvs'] = {}
        self.defer_parse = []
        for line in fil:
            state['file'] = fil.File()
            state['line'] = fil.Line()
            line = line.split('#', 1)[0].strip()

            tokens = line.split()
            if not tokens:
                continue

            key = tokens[0].upper()
            if key == 'ATTRIBUTE':
                self.__ParseAttribute(state, tokens)
            elif key == 'VALUE':
                self.__ParseValue(state, tokens, True)
            elif key == 'VENDOR':
                self.__ParseVendor(state, tokens)
            elif key == 'BEGIN-VENDOR':
                self.__ParseBeginVendor(state, tokens)
            elif key == 'END-VENDOR':
                self.__ParseEndVendor(state, tokens)

        for state, tokens in self.defer_parse:
            key = tokens[0].upper()
            if key == 'VALUE':
                self.__ParseValue(state, tokens, False)
        self.defer_parse = []
