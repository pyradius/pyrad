#!/usr/bin/python

from setuptools import setup, find_packages

version = "1.2"

setup(name                 = "pyrad",
      version              = version,
      author               = "Wichert Akkerman",
      author_email         = "wichert@wiggy.net",
      url                  = "http://www.wiggy.net/code/pyrad/",
      license              = "BSD",
      description          = "RADIUS tools",
      long_description     = open("README.txt").read() + "\n" +
                             open("CHANGES.txt").read(),
      classifiers          = [
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Systems Administration :: Authentication/Directory",
        ],
      packages             = find_packages(exclude=['tests']),
      keywords             = [ "radius", "authentication" ],
      zip_safe             = True,
      include_package_data = True,
      tests_require        = "nose>=0.10.0b1",
      test_suite           = "nose.collector",
      )
