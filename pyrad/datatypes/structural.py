"""
structural.py

Contains all structural datatypes
"""
import struct

from abc import ABC
from pyrad.datatypes import base
from pyrad.parser import ParserTLV
from pyrad.utility import tlv_name_to_codes, vsa_name_to_codes

parser_tlv = ParserTLV()

class AbstractStructural(base.AbstractDatatype, ABC):
    """
    abstract class for structural datatypes
    """

class Tlv(AbstractStructural):
    """
    structural datatype class for TLV
    """
    def __init__(self):
        super().__init__('tlv')

    def encode(self, attribute, decoded, *args, **kwargs):
        encoding = b''
        for key, value in decoded.items():
            encoding += attribute.children[key].encode(value, )

        if len(encoding) + 2 > 255:
            raise ValueError('TLV length too long for one packet')

        return (struct.pack('!B', attribute.number)
                + struct.pack('!B', len(encoding) + 2)
                + encoding)

    def get_value(self, attribute: 'Attribute', packet, offset):
        sub_attrs = {}

        _, outer_len = struct.unpack('!BB', packet[offset:offset + 2])[0:2]

        if outer_len < 3:
            raise ValueError('TLV length too short')
        if offset + outer_len > len(packet):
            raise ValueError('TLV length too long')

        # move cursor to TLV value
        cursor = offset + 2
        while cursor < offset + outer_len:
            (sub_type, sub_len) = struct.unpack(
                '!BB', packet[cursor:cursor + 2]
            )

            if sub_len < 3:
                raise ValueError('TLV length field too small')

            sub_value, sub_offset = attribute[sub_type].get_value(packet, cursor)
            sub_attrs.setdefault(sub_type, []).append(sub_value)

            cursor += sub_offset
        return sub_attrs, outer_len

    def print(self, attribute, decoded, *args, **kwargs):
        sub_attr_strings = [sub_attr.print()
                            for sub_attr in attribute.children]
        return f"{attribute.name} = {{ {', '.join(sub_attr_strings)} }}"

    def parse(self, dictionary, string, *args, **kwargs):
        return tlv_name_to_codes(dictionary, parser_tlv.parse(string))

class Vsa(AbstractStructural):
    """
    structural datatype class for VSA
    """
    def __init__(self):
        super().__init__('vsa')

        #  used for get_value()
        self.tlv = Tlv()

    def encode(self, attribute, decoded, *args, **kwargs):
        encoding = b''

        for key, value in decoded.items():
            encoding += attribute.children[key].encode(value, )

        return (struct.pack('!B', attribute.number)
                + struct.pack('!B', len(encoding) + 4)
                + struct.pack('!L', attribute.vendor)
                + encoding)

    def get_value(self, attribute: 'Attribute', packet, offset):
        values = {}

        # currently, a list of (code, value) pair is returned. with the v4
        # update, a single (nested) object will be returned
        # values = []

        (_, length) = struct.unpack('!BB', packet[offset:offset + 2])
        if length < 8:
            return {packet[offset + 2:offset + length]: {}}, length

        vendor = struct.unpack('!L', packet[offset + 2:offset + 6])[0]

        cursor = offset + 6
        while cursor < offset + length:
            (sub_type, _) = struct.unpack('!BB', packet[cursor:cursor + 2])

            values[sub_type], sub_offset = attribute[vendor][sub_type].get_value(packet, cursor)
            cursor += sub_offset

        return {vendor: values}, length

    def print(self, attribute, decoded, *args, **kwargs):
        sub_attr_strings = [sub_attr.print()
                            for sub_attr in attribute.children]
        return f"Vendor-Specific = {{ {attribute.vendor} = {{ {', '.join(sub_attr_strings)} }}"

    def parse(self, dictionary, string, *args, **kwargs):
        return vsa_name_to_codes(dictionary, parser_tlv.parse(string))
