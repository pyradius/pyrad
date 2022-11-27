#!/usr/bin/env python

from setuptools import setup, find_packages

import pyrad

setup(name='pyrad',
      version=pyrad.__version__,
      author='Istvan Ruzman, Christian Giese',
      author_email='istvan@ruzman.eu, developer@gicnet.de',
      url='https://github.com/pyradius/pyrad',
      license='BSD',
      description='RADIUS tools',
      long_description=open('README.rst').read(),
      classifiers=[
          'Development Status :: 6 - Mature',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: BSD License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3.6',
          'Programming Language :: Python :: 3.7',
          'Programming Language :: Python :: 3.8',
          'Programming Language :: Python :: 3.9',
          'Programming Language :: Python :: 3.10',
          'Topic :: Software Development :: Libraries :: Python Modules',
          'Topic :: System :: Systems Administration :: Authentication/Directory',
      ],
      packages=find_packages(exclude=['tests']),
      keywords=['radius', 'authentication'],
      zip_safe=True,
      include_package_data=True,
      install_requires=['six'],
      tests_require='nose>=0.10.0b1',
      test_suite='nose.collector',
      )
