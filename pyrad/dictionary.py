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
from pyrad import tools
from pyrad import dictfile
from copy import copy
import logging

__docformat__ = 'epytext en'


DATATYPES = frozenset(['string', 'ipaddr', 'integer', 'date', 'octets',
                       'abinary', 'ipv6addr', 'ipv6prefix', 'short', 'byte',
                       'signed', 'ifid', 'ether', 'tlv', 'integer64'])


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
    def __init__(self, name, code, datatype, is_sub_attribute=False, vendor='', values=None,
                 encrypt=0, has_tag=False):
        if datatype not in DATATYPES:
            raise ValueError('Invalid data type')
        self.name = name
        self.code = code
        self.type = datatype
        self.vendor = vendor
        self.encrypt = encrypt
        self.has_tag = has_tag
        self.values = bidict.BiDict()
        self.sub_attributes = {}
        self.parent = None
        self.is_sub_attribute = is_sub_attribute
        if values:
            for (key, value) in values.items():
                self.values.Add(key, value)


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

        if dict:
            self.ReadDictionary(dict)

        for i in dicts:
            self.ReadDictionary(i)

    def __len__(self):
        return len(self.attributes)

    def __getitem__(self, key):
        return self.attributes[key]

    def __contains__(self, key):
        return key in self.attributes

    has_key = __contains__

    def __ParseAttribute(self, state, tokens):
        if not len(tokens) in [4, 5]:
            raise ParseError(
                'Incorrect number of tokens for attribute definition',
                name=state['file'],
                line=state['line'])

        vendor = state['vendor']
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
                if not self.vendors.HasForward(vendor):
                    if vendor == "concat":
                        # ignore attributes with concat (freeradius compat.)
                        return None
                    else:
                        raise ParseError('Unknown vendor ' + vendor,
                                         file=state['file'],
                                         line=state['line'])

        (attribute, code, datatype) = tokens[1:4]

        codes = code.split('.')
        is_sub_attribute = (len(codes) > 1)
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
        elif len(codes) == 1:
            code = int(codes[0])
            parent_code = None
        else:
            raise ParseError('nested tlvs are not supported')

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'])
        if vendor:
            if is_sub_attribute:
                key = (self.vendors.GetForward(vendor), parent_code, code)
            else:
                key = (self.vendors.GetForward(vendor), code)
        else:
            if is_sub_attribute:
                key = (parent_code, code)
            else:
                key = code

        self.attrindex.Add(attribute, key)
        self.attributes[attribute] = Attribute(attribute, code, datatype, is_sub_attribute, vendor, encrypt=encrypt, has_tag=has_tag)
        if datatype == 'tlv':
            # save attribute in tlvs
            state['tlvs'][code] = self.attributes[attribute]
        if is_sub_attribute:
            # save sub attribute in parent tlv and update their parent field
            state['tlvs'][parent_code].sub_attributes[code] = attribute
            self.attributes[attribute].parent = state['tlvs'][parent_code]

    def __ParseValue(self, state, tokens, defer):
        if len(tokens) != 4:
            raise ParseError('Incorrect number of tokens for value definition',
                             file=state['file'],
                             line=state['line'])

        (attr, key, value) = tokens[1:]

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            raise ParseError('Value defined for unknown attribute ' + attr,
                             file=state['file'],
                             line=state['line'])

        if adef.type in ['integer', 'signed', 'short', 'byte', 'integer64']:
            value = int(value, 0)
        value = tools.EncodeAttr(adef.type, value)
        self.attributes[attr].values.Add(key, value)

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

        (vendorname, vendor) = tokens[1:3]
        self.vendors.Add(vendorname, int(vendor, 0))

    def __ParseBeginVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                    'Incorrect number of tokens for begin-vendor statement',
                    file=state['file'],
                    line=state['line'])

        vendor = tokens[1]

        if not self.vendors.HasForward(vendor):
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % vendor,
                    file=state['file'],
                    line=state['line'])

        state['vendor'] = vendor

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
