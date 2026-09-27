# dictionary.py
#
# Copyright 2002,2005,2007,2016 Wichert Akkerman <wichert@wiggy.net>
"""
RADIUS uses dictionaries to define the attributes that can
be used in packets. The Dictionary class stores the attribute
definitions from one or more dictionary files.

Dictionary files are text files with one command per line.
Comments are specified by starting with a # character, and empty
lines are ignored.

The commands supported are::

  ATTRIBUTE <attribute> <code> <type> [<vendor>|<flags>]
  specify an attribute and its type

  VALUE <attribute> <valuename> <value>
  specify a named value of an attribute

  VENDOR <name> <id>
  specify a vendor ID

  BEGIN-VENDOR <vendorname>
  begin definition of vendor attributes

  END-VENDOR <vendorname>
  end definition of vendor attributes

  $INCLUDE <filename>
  read another dictionary file, relative to the current one

The attribute flags are a comma separated list of:

  has_tag
  the attribute is tagged (RFC 2868)

  encrypt=1
  User-Password encryption (RFC 2865 section 5.2), which is not applied
  automatically, see AuthPacket.PwCrypt and AuthPacket.PwDecrypt

  encrypt=2
  salt encryption (RFC 2868 section 3.5), applied automatically

The FreeRADIUS flags secret, virtual and concat are accepted and ignored.

FreeRADIUS dictionaries also define attributes that pyrad cannot encode or
decode. These are skipped with a warning, so that the FreeRADIUS dictionary
files can be read as they are:

- attributes of the types listed in UNSUPPORTED_DATATYPES, such as the
  RFC 6929 extended attributes, and their sub-attributes
- attributes with the array flag
- TLVs nested more than one level deep
- attributes of vendors with a format other than format=1,1 (VENDOR)
- vendor attributes in a BEGIN-VENDOR block with a format= option, which
  are extended vendor-specific attributes (RFC 6929)

VALUE definitions for skipped attributes are ignored, and VALUE definitions
for unknown attributes are ignored with a warning. Received attributes
that were skipped are decoded as undefined attributes.

The datatypes currently supported are:

+---------------+----------------------------------------------+
| type          | description                                  |
+===============+==============================================+
| string        | UTF-8 string                                 |
+---------------+----------------------------------------------+
| ipaddr        | IPv4 address                                 |
+---------------+----------------------------------------------+
| date          | 32 bits UNIX timestamp                       |
+---------------+----------------------------------------------+
| octets        | arbitrary binary data                        |
+---------------+----------------------------------------------+
| abinary       | Ascend binary filter                         |
+---------------+----------------------------------------------+
| ipv6addr      | 16 octets in network byte order              |
+---------------+----------------------------------------------+
| ipv6prefix    | up to 18 octets in network byte order        |
+---------------+----------------------------------------------+
| integer       | 32 bits unsigned number                      |
+---------------+----------------------------------------------+
| signed        | 32 bits signed number                        |
+---------------+----------------------------------------------+
| short         | 16 bits unsigned number                      |
+---------------+----------------------------------------------+
| byte          | 8 bits unsigned number                       |
+---------------+----------------------------------------------+
| tlv           | nested type-length-value                     |
+---------------+----------------------------------------------+
| integer64     | 64 bits unsigned number                      |
+---------------+----------------------------------------------+
| ifid          | 8 octets IPv6 interface identifier, written  |
|               | as hhhh:hhhh:hhhh:hhhh                       |
+---------------+----------------------------------------------+
| ether         | 6 octets of hh:hh:hh:hh:hh:hh                |
|               | where 'h' is hex digits, upper or lowercase. |
+---------------+----------------------------------------------+
"""
import logging

from pyrad import bidict
from pyrad import tools
from pyrad import dictfile
from copy import copy

__docformat__ = 'epytext en'

logger = logging.getLogger('pyrad')


DATATYPES = frozenset(['string', 'ipaddr', 'integer', 'date', 'octets',
                       'abinary', 'ipv6addr', 'ipv6prefix', 'short', 'byte',
                       'signed', 'ifid', 'ether', 'tlv', 'integer64'])

# FreeRADIUS data types which pyrad does not support. Attributes of these
# types are skipped with a warning instead of failing the parse.
UNSUPPORTED_DATATYPES = frozenset(['vsa', 'extended', 'long-extended', 'evs',
                                   'ipv4prefix', 'combo-ip', 'bool', 'uint16',
                                   'uint32'])

# Attribute flags; a fifth ATTRIBUTE column that contains one of them is a
# list of flags instead of a vendor name.
ATTRIBUTE_FLAGS = frozenset(['has_tag', 'encrypt', 'secret', 'array',
                             'virtual', 'concat'])


class ParseError(Exception):
    """Dictionary parser exceptions.

    :ivar msg:  Error message
    :type msg:  string
    :ivar file: Name of the dictionary file
    :type file: string
    :ivar line: Line number on which the error occurred
    :type line: integer
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


class Dictionary:
    """RADIUS dictionary class.
    This class stores all information about vendors, attributes and their
    values as defined in RADIUS dictionary files.

    :ivar vendors:    bidict mapping vendor name to vendor code
    :type vendors:    bidict
    :ivar attrindex:  bidict mapping attribute name to attribute code
                      (or (vendor code, attribute code) tuple)
    :type attrindex:  bidict
    :ivar attributes: mapping of attribute name to attribute class
    :type attributes: dict
    :ivar skipped_attributes: names of the attributes that were skipped
                              because pyrad does not support them
    :type skipped_attributes: set
    """

    def __init__(self, dict=None, *dicts):
        """
        :param dict:  path of dictionary file or file-like object to read
        :type dict:   string or file
        :param dicts: further dictionaries to read
        :type dicts:  strings or files
        """
        self.vendors = bidict.BiDict()
        self.vendors.Add('', 0)
        self.attrindex = bidict.BiDict()
        self.attributes = {}
        self.defer_parse = []
        self.skipped_attributes = set()
        # vendors whose attribute format is not the RFC 2865 one
        self._unsupported_vendors = set()

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

    def __SkipAttribute(self, state, name, reason):
        self.skipped_attributes.add(name)
        state['skipped'].append(reason)
        logger.debug('%s(%d): skipping attribute %s: %s',
                     state['file'], state['line'], name, reason)

    def __ParseAttribute(self, state, tokens):
        if len(tokens) not in [4, 5]:
            raise ParseError(
                'Incorrect number of tokens for attribute definition',
                file=state['file'],
                line=state['line'])

        vendor = state['vendor']
        has_tag = False
        encrypt = 0
        array = False
        if len(tokens) >= 5:
            def keyval(o):
                kv = o.split('=')
                if len(kv) == 2:
                    return (kv[0], kv[1])
                else:
                    return (kv[0], None)
            options = [keyval(o) for o in tokens[4].split(',')]
            is_flags = any(key in ATTRIBUTE_FLAGS for (key, val) in options)
            if self.vendors.HasForward(tokens[4]) and \
                    not any(key in ('has_tag', 'encrypt')
                            for (key, val) in options):
                vendor = tokens[4]
            elif not is_flags:
                raise ParseError('Unknown vendor ' + tokens[4],
                                 file=state['file'],
                                 line=state['line'])
            for (key, val) in options if is_flags else []:
                if key == 'has_tag':
                    has_tag = True
                elif key == 'encrypt':
                    if val not in ['1', '2', '3']:
                        raise ParseError(
                                'Illegal attribute encryption: %s' % val,
                                file=state['file'],
                                line=state['line'])
                    encrypt = int(val)
                elif key == 'array':
                    array = True

        (attribute, code, datatype) = tokens[1:4]

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

        datatype = datatype.split("[")[0]

        if datatype not in DATATYPES and datatype not in UNSUPPORTED_DATATYPES:
            raise ParseError('Illegal type: ' + datatype,
                             file=state['file'],
                             line=state['line'])

        vendor_code = self.vendors.GetForward(vendor)
        if len(codes) > 1 and (vendor_code, codes[0]) in state['skipped_codes']:
            return self.__SkipAttribute(
                state, attribute, 'sub-attribute of unsupported attribute')
        if state['vendor_format']:
            return self.__SkipAttribute(
                state, attribute, 'extended vendor-specific attribute')
        if vendor in self._unsupported_vendors:
            return self.__SkipAttribute(state, attribute, 'vendor format')
        if datatype in UNSUPPORTED_DATATYPES:
            if len(codes) == 1:
                state['skipped_codes'].add((vendor_code, codes[0]))
            return self.__SkipAttribute(state, attribute,
                                        'data type ' + datatype)
        if array:
            return self.__SkipAttribute(state, attribute, 'array flag')
        if len(codes) > 2 or (len(codes) == 2 and datatype == 'tlv'):
            return self.__SkipAttribute(state, attribute, 'nested TLV')

        is_sub_attribute = (len(codes) > 1)
        if len(codes) == 2:
            code = int(codes[1])
            parent_code = int(codes[0])
            if parent_code not in state['tlvs']:
                raise ParseError(
                    'Sub-attribute %s of unknown TLV %d' % (attribute,
                                                            parent_code),
                    file=state['file'],
                    line=state['line'])
        else:
            code = int(codes[0])
            parent_code = None

        if vendor:
            if is_sub_attribute:
                key = (vendor_code, parent_code, code)
            else:
                key = (vendor_code, code)
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

        if attr in self.skipped_attributes and attr not in self.attributes:
            return

        try:
            adef = self.attributes[attr]
        except KeyError:
            if defer:
                self.defer_parse.append((copy(state), copy(tokens)))
                return
            # FreeRADIUS dictionaries contain a few of these, so warn
            # instead of failing the parse
            logger.warning('%s(%d): ignoring value defined for unknown '
                           'attribute %s', state['file'], state['line'], attr)
            return

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

        (vendorname, vendor) = tokens[1:3]

        # pyrad only encodes the RFC 2865 vendor attribute format (1 octet
        # type, 1 octet length), attributes of vendors with another format
        # are skipped
        if len(tokens) == 4:
            fmt = tokens[3].split('=')
            if fmt[0] != 'format':
                raise ParseError(
                        "Unknown option '%s' for vendor definition" % (fmt[0]),
                        file=state['file'],
                        line=state['line'])
            try:
                fmtargs = fmt[1].split(',')
                # ",c": WiMAX continuation octet
                continuation = len(fmtargs) == 3 and fmtargs[2] == 'c'
                if continuation:
                    fmtargs = fmtargs[:2]
                (token, length) = tuple(int(a) for a in fmtargs)
            except ValueError:
                raise ParseError(
                        'Syntax error in vendor specification',
                        file=state['file'],
                        line=state['line'])
            if token not in [1, 2, 4] or length not in [0, 1, 2]:
                raise ParseError(
                    'Unknown vendor format specification %s' % (fmt[1]),
                    file=state['file'],
                    line=state['line'])
            if (token, length, continuation) != (1, 1, False):
                self._unsupported_vendors.add(vendorname)
            else:
                self._unsupported_vendors.discard(vendorname)

        self.vendors.Add(vendorname, int(vendor, 0))

    def __ParseBeginVendor(self, state, tokens):
        if len(tokens) not in [2, 3]:
            raise ParseError(
                    'Incorrect number of tokens for begin-vendor statement',
                    file=state['file'],
                    line=state['line'])

        # BEGIN-VENDOR <vendor> format=<Extended-Vendor-Specific attribute>
        # defines extended vendor-specific attributes (RFC 6929), which are
        # skipped
        vendor_format = None
        if len(tokens) == 3:
            if not tokens[2].startswith('format='):
                raise ParseError(
                        "Unknown option '%s' for begin-vendor statement" %
                        tokens[2],
                        file=state['file'],
                        line=state['line'])
            vendor_format = tokens[2][len('format='):]

        vendor = tokens[1]

        if not self.vendors.HasForward(vendor):
            raise ParseError(
                    'Unknown vendor %s in begin-vendor statement' % vendor,
                    file=state['file'],
                    line=state['line'])

        state['vendor'] = vendor
        state['vendor_format'] = vendor_format

    def __ParseEndVendor(self, state, tokens):
        if len(tokens) != 2:
            raise ParseError(
                'Incorrect number of tokens for end-vendor statement',
                file=state['file'],
                line=state['line'])

        vendor = tokens[1]

        if state['vendor'] != vendor:
            raise ParseError(
                    'Ending non-open vendor ' + vendor,
                    file=state['file'],
                    line=state['line'])
        state['vendor'] = ''
        state['vendor_format'] = None

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
        state['vendor_format'] = None
        state['tlvs'] = {}
        state['skipped'] = []
        state['skipped_codes'] = set()
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

        if state['skipped']:
            reasons = sorted(set(state['skipped']))
            logger.warning('Skipped %d unsupported dictionary attributes (%s)',
                           len(state['skipped']), ', '.join(reasons))
