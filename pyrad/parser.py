"""
BNF form of string TLVs

<tlv> ::= <vp>
<vp>  ::= <string> " = " (<string> | ("{ " <vps> " }"))
<vps> ::= <vp> (", " <vp>)*
<string> ::= ([A-Z] | [a-z] | [0-9])+
"""

class ParseError(Exception):
    pass

class ParserTLV:
    """
    Recursive descent parser for TLVs (and similar structural datatypes)
    """
    def __init__(self):
        self.__buffer: str = None
        self.__cursor: int = None

    def parse(self, buffer):
        self.__buffer = buffer
        self.__cursor = 0

        return self.__state_vp()

    def __state_vp(self):
        vp = {}

        #  get key for current vp
        key = self.__state_string()

        #  check for and move past '=' token
        if not self.__buffer[self.__cursor] == '=':
            raise ParseError('Did not find equal sign at position')
        self.__cursor += 1
        self.__remove_whitespace()

        if self.__buffer[self.__cursor] == '{':
            # move past '{' token
            self.__cursor += 1
            self.__remove_whitespace()

            value = self.__state_vps()

            #  check for and move past '}' token
            if not self.__buffer[self.__cursor] == '}':
                raise ParseError('Did not find closing bracket')
            self.__cursor += 1
            self.__remove_whitespace()
        else:
            value = self.__state_string()

        vp[key] = value
        return vp

    def __state_vps(self):
        vps = {}
        while True:
            vps.update(self.__state_vp())
            if not self.__buffer[self.__cursor] == ',':
                break
            # move past ',' token
            self.__cursor += 1
            self.__remove_whitespace()
        self.__remove_whitespace()
        return vps

    def __state_string(self):
        string = self.__get_word()
        self.__remove_whitespace()
        return string

    def __get_word(self):
        cursor_start = self.__cursor
        while self.__cursor < len(self.__buffer):
            if (not self.__buffer[self.__cursor].isalnum()
                    and self.__buffer[self.__cursor] not in ['-', '_']):
                return self.__buffer[cursor_start:self.__cursor]
            self.__cursor += 1
        return self.__buffer[cursor_start:self.__cursor]

    def __remove_whitespace(self):
        while self.__cursor < len(self.__buffer):
            if not self.__buffer[self.__cursor].isspace():
                return
            self.__cursor += 1
        return
