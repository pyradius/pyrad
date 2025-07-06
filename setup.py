#!/usr/bin/env python

from setuptools import setup, find_packages

import pyrad2

setup(name='pyrad2',
      version=pyrad2.__version__,
      author='Nicholas Amorim, Istvan Ruzman, Christian Giese',
      author_email='nicholas@bloomshield.ee, istvan@ruzman.eu, developer@gicnet.de',
      url='https://github.com/nicholasamorim/pyrad2',
      license='BSD',
      description='RADIUS tools',
      long_description=open('README.rst').read(),
      classifiers=[
          'Development Status :: 6 - Mature',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 3.12',
          'Programming Language :: Python :: 3.13',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Systems Administration :: Authentication/Directory',
      ],
      packages=find_packages(exclude=['tests']),
      keywords=['radius', 'authentication'],
      zip_safe=True,
      include_package_data=True,
      tests_require='nose>=0.10.0b1',
      test_suite='nose.collector',
      )
