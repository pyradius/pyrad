#!/usr/bin/python

from setuptools import setup, find_packages


version = '2.1'


setup(name='pyrad',
      version=version,
      author='Wichert Akkerman',
      author_email='wichert@wiggy.net',
      url='https://github.com/wichert/pyrad',
      license='BSD',
      description='RADIUS tools',
      long_description=open('README.rst').read(),
      classifiers=[
       'Development Status :: 6 - Mature',
       'Intended Audience :: Developers',
       'License :: OSI Approved :: BSD License',
       'Programming Language :: Python :: 2.6',
       'Programming Language :: Python :: 2.7',
       'Programming Language :: Python :: 3.2',
       'Topic :: Software Development :: Libraries :: Python Modules',
       'Topic :: System :: Systems Administration :: Authentication/Directory',
       ],
      packages=find_packages(exclude=['tests']),
      keywords=['radius', 'authentication'],
      zip_safe=True,
      include_package_data=True,
      install_requires=['six', 'netaddr'],
      tests_require='nose>=0.10.0b1',
      test_suite='nose.collector',
      )
