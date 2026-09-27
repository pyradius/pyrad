# dictfile.py
#
# Copyright 2009 Kristoffer Gronlund <kristoffer.gronlund@purplescout.se>

""" Dictionary File

Implements an iterable file format that handles the
RADIUS $INCLUDE directives behind the scene.
"""

import os


class _Node:
    """Dictionary file node

    A single dictionary file.
    """
    __slots__ = ('name', 'lines', 'current', 'length', 'dir', 'path')

    def __init__(self, fd, name, parentdir, path=None):
        # real path of the file, None for file-like objects
        self.path = path
        self.lines = fd.readlines()
        self.length = len(self.lines)
        self.current = 0
        self.name = os.path.basename(name)
        path = os.path.dirname(name)
        if os.path.isabs(path):
            self.dir = path
        else:
            self.dir = os.path.join(parentdir, path)

    def Next(self):
        if self.current >= self.length:
            return None
        self.current += 1
        return self.lines[self.current - 1]


class DictFile:
    """Dictionary file class

    An iterable file type that handles $INCLUDE
    directives internally. $INCLUDE- includes a file only if it exists.
    """
    __slots__ = ('stack')

    def __init__(self, fil):
        """
        @param fil: a dictionary file to parse
        @type fil: string or file
        """
        self.stack = []
        self.__ReadNode(fil)

    def __ReadNode(self, fil, optional=False):
        parentdir = self.__CurDir()
        if isinstance(fil, str):
            if os.path.isabs(fil):
                fname = fil
            else:
                fname = os.path.join(parentdir, fil)
            if optional and not os.path.exists(fname):
                return
            path = os.path.realpath(fname)
            if any(node.path == path for node in self.stack):
                # imported here, pyrad.dictionary imports this module
                from pyrad.dictionary import ParseError
                raise ParseError('Recursive include of ' + fil,
                                 file=self.File(), line=self.Line())
            with open(fname, "rt") as fd:
                node = _Node(fd, fil, parentdir, path)
        else:
            node = _Node(fil, '', parentdir)
        self.stack.append(node)

    def __CurDir(self):
        if self.stack:
            return self.stack[-1].dir
        else:
            return os.path.realpath(os.curdir)

    def __GetInclude(self, line):
        """Returns (file name, optional) of an include directive, or
        (None, False)
        """
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() in ('$INCLUDE', '$INCLUDE-'):
            return (" ".join(tokens[1:]), tokens[0].endswith('-'))
        else:
            return (None, False)

    def Line(self):
        """Returns line number of current file
        """
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def File(self):
        """Returns name of current file
        """
        if self.stack:
            return self.stack[-1].name
        else:
            return ''

    def __iter__(self):
        return self

    def __next__(self):
        while self.stack:
            line = self.stack[-1].Next()
            if line is None:
                self.stack.pop()
            else:
                (inc, optional) = self.__GetInclude(line)
                if inc:
                    self.__ReadNode(inc, optional)
                else:
                    return line
        raise StopIteration
