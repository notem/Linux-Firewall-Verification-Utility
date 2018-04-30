# Overview

This project consists of two-parts: 
   1) a Python 3 extension module (written in C)
      * This module implements an efficient version of a firewall property verification algorithm.
      * This module is used by the other scripts in this project.
      
   2) three python scripts
      * ``fverify.py`` is the primary script which applies the algorithm to *iptables* exports
      * ``benchmark.py`` may be used examine the performance of the algorithm
      * ``test.py`` demonstrates functionality on a small toy firewall


## Python Module Installation

1) run ``module/setup.py build`` to build the python module
2) run ``module/setup.py install`` to install the python module (may need administrative priveledges)
3) add ``import firewall_verifier`` to python 3 script to include the module

## Using ``fverify.py``

1) Install the ``firewall_verifier`` python module (see above)
2) Export your netfilter filter settings using the *iptables-save* command
    * (optional) remove rules using unsupported fields
    * Ex. ``iptables-save > firewall.txt``
3) Decide upon a firewall property to examine and run the *fverify.py*.
    * The script accepts arguments using the same flags as *iptables*.
    * The script requires that the chain, jump, and firewall input file.
    * Ex. ``python3 fverify.py -A INPUT -s 169.254.0.0/16 -j DENY -file firewall.txt``
    
## Contributing

If you're interested in contributing we recommend one of the following actions...

* make a pull request
* contact a contributor
* fork and do it better

### Modifying Module Source

A small test program, implemented in C, is provided to allow a developer to more easily diagnose errors.
This program can be compiled using the ``cmake`` utility. 
Don't rely to heavily on the test program, it is not exhaustive (or extensive, or particularly valuable).
