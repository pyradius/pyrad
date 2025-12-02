"""
base.py

Contains base datatype
"""
from abc import ABC, abstractmethod

class AbstractDatatype(ABC):
    """
    Root of entire datatype class hierarchy
    """
    def __init__(self, name: str):
        """

        :param name: str representation of datatype
        :type name: str
        """
        self.name = name

    @abstractmethod
    def encode(self, attribute: 'Attribute', decoded: any,
               *args, **kwargs) -> bytes:
        """
        python data structure into bytestring
        :param attribute: dictionary attribute
        :type attribute: pyrad.dictionary.Attribute class
        :param decoded: decoded value
        :type decoded: any
        :param args:
        :param kwargs:
        :return: bytestring encoding
        :rtype: bytes
        """

    @abstractmethod
    def print(self, attribute: 'Attribute', decoded: any,
              *args, **kwargs) -> str:
        """
        python data structure into string
        :param attribute: dictionary attribute
        :type attribute: pyrad.dictionary.Attribute class
        :param decoded: decoded value
        :type decoded: any
        :param args:
        :param kwargs:
        :return: string representation
        :rtype: str
        """

    @abstractmethod
    def parse(self, dictionary: 'Dictionary', string: str,
              *args, **kwargs) -> any:
        """
        python data structure from string
        :param dictionary: RADIUS dictionary
        :type dictionary: pyrad.dictionary.Dictionary class
        :param string: string representation of object
        :type string: str
        :param args:
        :param kwargs:
        :return: python datat structure
        :rtype: any
        """

    @abstractmethod
    def get_value(self, attribute: 'Attribute', packet: bytes, offset: int) -> (tuple[((int, ...), bytes | dict), ...], int):
        """
        gets encapsulated value

        returns a tuple of encapsulated value and an int of number of bytes
        read. the tuple contains one or more (key, value) pairs, with each key
        being a full OID (tuple of ints) and the value being a bytestring (for
        leaf attributes), or a dict (for TLVs).

        future work will involve the removal of the dictionary and code
        arguments. they are currently needed for VSA's get_value() where both
        values are needed to fetch vendor attributes since vendor attributes
        are not stored as a sub-attribute of the Vendor-Specific attribute.

        future work will also change the return value. in place of returning a
        tuple of (key, value) pairs, a single bytestring or dict will be
        returned.

        :param attribute: dictionary attribute
        :type attribute: pyrad.dictionary.Attribute class
        :param packet: entire packet bytestring
        :type packet: bytes
        :param offset: position in packet where current attribute begins
        :type offset: int
        :return: encapsulated value, bytes read
        :rtype: any, int
        """
