#!/usr/bin/python3
#
# Script to build project python3 module
#  run ``setup.py build`` & ``setup.py install``
#
from distutils.core import setup, Extension

module1 = Extension('firewall_verifier',
                    sources=['src/python.c', 'src/utils.c/algorithm.c'])

setup(name='FirewallVerifier',
        version='1.0',
        description='This is a demo package',
        ext_modules=[module1])