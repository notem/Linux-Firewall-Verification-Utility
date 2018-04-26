#!/usr/bin/python3
#
# Script to build project python3 module
#  run ``setup.py build`` & ``setup.py install``
#
from distutils.core import setup, Extension

module1 = Extension('firewall_verifier',
                    sources=['src/python.c', 'src/algorithm.c'])

setup(name='FirewallVerifier',
      version='1.0',
      description='Build 5-tuple firewalls and verify properties',
      ext_modules=[module1])
