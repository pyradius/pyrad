#!/usr/bin/python

from distutils.core import setup

setup(	name		= "pyrad",
	version		= "0.9",
	author		= "Wichert Akkerman",
	author_email	= "wichert@wiggy.net",
	url		= "http://www.wiggy.net/code/pyrad/",
	license		= "BSD",
	description	= "RADIUS client tools",
	long_description= 
'''pyrad is an implementation of a RADIUS client as described in RFC2865.
It takes care of all the details like building RADIUS packets, sending
them and decoding responses.''',
	packages	= [ "pyrad" ],
	keywords	= [ "radius", "authentication" ],
	package_dir	= { "pyrad" : "src" })
