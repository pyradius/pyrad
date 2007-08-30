#!/usr/bin/python

from setuptools import setup, find_packages

setup(	name		= "pyrad",
	version		= "0.9",
	author		= "Wichert Akkerman",
	author_email	= "wichert@simplon.biz",
	url		= "http://www.wiggy.net/code/pyrad/",
	license		= "BSD",
	description	= "RADIUS client tools",
	long_description= open("README.txt").read(),
        classifiers     = [
            "Intended Audience :: Developers",
            "License :: OSI Approved :: BSD License",
            "Programming Language :: Python",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "Topic :: System :: Systems Administration :: Authentication/Directory",
            ]
	packages	= [ "pyrad" ],
	keywords	= [ "radius", "authentication" ],
	package_dir	= { "pyrad" : "src" },
        zip_safe        = True,
        include_package_data = True,
        )
