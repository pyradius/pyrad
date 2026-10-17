# dictfile.py
#
# Copyright 2009 Kristoffer Gronlund <kristoffer.gronlund@purplescout.se>

"""Dictionary file reader.

Implements an iterable over the lines of a dictionary file that handles
the $INCLUDE directives behind the scenes.
"""

import os


class _Node:
    """A single dictionary file."""
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
    """Iterate over the lines of a dictionary file and its includes.

    $INCLUDE directives are handled internally: the lines of the included
    file are returned in place of the directive. A relative file name is
    relative to the directory of the current file, or to the current
    working directory for a file-like object. $INCLUDE- includes a file
    only if it exists. A recursive include raises a
    :class:`pyrad.dictionary.ParseError`.
    """
    __slots__ = ('stack')

    def __init__(self, fil):
        """
        :param fil: path of a dictionary file or a file-like object
        :type  fil: str or io.TextIOBase
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
        """Return (file name, optional) of an include directive.

        Returns (None, False) for other lines.
        """
        line = line.split("#", 1)[0].strip()
        tokens = line.split()
        if tokens and tokens[0].upper() in ('$INCLUDE', '$INCLUDE-'):
            return (" ".join(tokens[1:]), tokens[0].endswith('-'))
        else:
            return (None, False)

    def Line(self):
        """Return the line number in the current file."""
        if self.stack:
            return self.stack[-1].current
        else:
            return -1

    def File(self):
        """Return the name of the current file."""
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
