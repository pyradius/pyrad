# dictionary.py
#
# Copyright 2002,2005 Wichert Akkerman <wichert@wiggy.net>

"""RADIUS dictionary

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


The datatypes currently supported are::

  string   - ASCII string
  ipaddr   - IPv4 address
  integer  - 32 bits signed number
  date     - 32 bits UNIX timestamp
  octets   - arbitrary binary data
  abinary  - ASCII encoded binary data
"""

__docformat__	= "epytext en"

import bidict, tools

class ParseError(Exception):
	"""Dictionary parser exceptions.

	@ivar msg:        Error message
	@type msg:        string
	@ivar filename:   Name of the file being parsed
	@type filename:   string
	@ivar linenumber: Line number on which the error occured
	@type linenumber: integer
	"""

	def __init__(self, msg=None, **data):
		self.msg=msg
		if data.has_key("filename"):
			self.filename=data["filename"]
		elif data.has_key("linenumber"):
			self.linenumber=data["linenumber"]
	
	def __str__(self):
		str=""
		if hasattr(self, "filename"):
			str+=self.filename
			if hasattr(self, "linenumber"):
				str+="(%d)" % self.linenumber
			str+=": "
		str+="Parse error"
		if self.msg:
			str+=": %s" % self.msg

		return str


class Attribute:
	def __init__(self, name, code, datatype, vendor="", values={}):
		assert datatype in ("string", "ipaddr", "integer", "date",
					"octets", "abinary", "ipv6addr", "ifid")
		self.name=name
		self.code=code
		self.type=datatype
		self.vendor=vendor
		self.values=bidict.BiDict()
		for (key,value) in values.items():
			self.values.Add(key, value)


class Dictionary:
	"""RADIUS dictionary class

	This class stores all information about vendors, attributes and their
	values as defined in RADIUS dictionary files.

	@ivar vendors:    bidict mapping vendor name to vendor code
	@type vendors:    bidict
	@ivar attrindex:  bidict mapping 
	@type attrindex:  bidict
	@ivar attributes: bidict mapping attribute name to attribute class
	@type attributes: bidict
	"""

	def __init__(self, dict=None, *dicts):
		"""
		@param dict:  dictionary file to read
		@type dict:   string
		@param dicts: list of dictionary files to read
		@type dicts:  sequence of strings
		"""
		self.vendors=bidict.BiDict()
		self.vendors.Add("", 0)
		self.attrindex=bidict.BiDict()
		self.attributes={}

		if dict:
			self.ReadDictionary(dict)

		for i in dicts:
			self.ReadDictionary(i)
	

	def __getitem__(self, key):
		return self.attributes[key]


	def has_key(self, key):
		return self.attributes.has_key(key)


	def __ParseAttribute(self, state, tokens):
		if not len(tokens) in [4,5]:
			raise ParseError, "Incorrect number of tokens for attribute definition"

		if len(tokens)>=5 and tokens[4].find("=")==-1:
			vendor=tokens[4]
			if not self.vendors.HasForward(vendor):
				raise ParseError, "Unknown vendor " + vendor
		else:
			vendor=state["vendor"]

		(attribute,code,datatype)=tokens[1:4]
		code=int(code)
		if not datatype in \
			("string", "ipaddr", "integer", "date",
			"octets", "abinary", "ipv6addr", "ifid"):
			raise ParseError, "Illegal type: " + datatype

		if vendor:
			key=(self.vendors.GetForward(vendor),code)
		else:
			key=code

		self.attrindex.Add(attribute, key)
		self.attributes[attribute]=Attribute(attribute, code, datatype, vendor)
	

	def __ParseValue(self, state, tokens):
		if len(tokens)!=4:
			raise ParseError, "Incorrect number of tokens for attribute definition"

		(attr, key, value)=tokens[1:]

		try:
			adef=self.attributes[attr]
		except KeyError:
			raise ParseError, "Value defined for unknown attribute " + attr

		if adef.type=="integer":
			value=int(value)
		value=tools.EncodeAttr(adef.type, value)
		self.attributes[attr].values.Add(key, value)


	def __ParseVendor(self, state, tokens):
		if len(tokens)!=3:
			raise ParseError, "Incorrect number of tokens for vendor definition"

		(vendorname,vendor)=tokens[1:]
		self.vendors.Add(vendorname, int(vendor))
	

	def __ParseBeginVendor(self, state, tokens):
		if len(tokens)!=2:
			raise ParseError, "Incorrect number of tokens for begin-vendor statement"

		vendor=tokens[1]

		if not self.vendors.HasForward(vendor):
			raise ParseError, "Unknown vendor %s in begin-vendor statement" % vendor

		state["vendor"]=vendor


	def __ParseEndVendor(self, state, tokens):
		if len(tokens)!=2:
			raise ParseError, "Incorrect number of tokens for end-vendor statement"

		vendor=tokens[1]

		if state["vendor"]!=vendor:
			raise ParseError, "Ending non-open vendor" + vendor

		state["vendor"]=""


	def ReadDictionary(self, file):
		"""Parse a dictionary file

		Reads a RADIUS dictionary file and merges its contents into the
		class instance.

		@param file: Name of dictionary file to parse
		@type file:  string
		"""

		fd=open(file, "rt")
		state={}
		state["vendor"]=""

		for line in fd.xreadlines():
			line=line.split("#", 1)[0].strip()

			tokens=line.split()
			if not tokens:
				continue

			if tokens[0]=="ATTRIBUTE":
				self.__ParseAttribute(state, tokens)
			elif tokens[0]=="VALUE":
				self.__ParseValue(state, tokens)
			elif tokens[0]=="VENDOR":
				self.__ParseVendor(state, tokens)
			elif tokens[0]=="BEGIN-VENDOR":
				self.__ParseBeginVendor(state, tokens)
			elif tokens[0]=="END-VENDOR":
				self.__ParseEndVendor(state, tokens)

		fd.close()

