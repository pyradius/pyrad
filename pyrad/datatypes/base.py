"""
base.py

Contains base datatype
"""
from abc import ABC, abstractmethod

class AbstractDatatype(ABC):
    """
    Root of entire datatype class hierarchy
    """
    def __init__(self, name):
        self.name = name

    @abstractmethod
    def encode(self, attribute, decoded, *args, **kwargs):
        """
        turns python data structure into bytes

        :param *args:
        :param **kwargs:
        :param attribute:
        :param decoded: python data structure to encode
        :return: encoded bytes
        """

    @abstractmethod
    def print(self, attribute, decoded, *args, **kwargs):
        """
        returns string representation of decoding

        :param *args:
        :param **kwargs:
        :param attribute: attribute object
        :param decoded: value pair
        :return: string
        """

    @abstractmethod
    def parse(self, dictionary, string, *args, **kwargs):
        """
        returns python structure from ASCII string

        :param *args:
        :param **kwargs:
        :param dictionary:
        :param string: ASCII string of attribute
        :return: python structure for attribute
        """

    @abstractmethod
    def get_value(self, dictionary, code, attribute, packet, offset):
        """
        retrieves the encapsulated value
        :param dictionary:
        :param code:
        :param *args:
        :param **kwargs:
        :param attribute: attribute value
        :param packet: packet
        :param offset: attribute starting position
        :return: encapsulated value, and bytes read
        """
