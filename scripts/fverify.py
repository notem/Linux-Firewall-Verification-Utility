#!/usr/bin/env python3
# date: 2018-04-25
# contributor(s):
#	Michael Rhodes, mjr2563@rit.edu
#   Nate Mathews, njm3308@rit.edu (minor contributions)
# description:
#	Command-line python tool to audit firewall policies in iptables. This 
#	tool imports a python module called firewall_verifier. Steps to install
#	this module can be found at:
#		https://github.com/notem/Linux-Firewall-Verification-Utility

import firewall_verifier as fv
from ipaddress import IPv4Address, IPv4Network
from socket import getprotobyname
from sys import argv, exit
from os import path

usageStatement = """	
Usage: fverify [policy] -file [filename]
	Specifying a policy: 
		use the same options you would use to create a rule in iptables
	Required parameters:
		-j | --jump [target]	specify the target (ADD/DROP)
		-A | --append [chain]	specify the chain to look at
		-file [filename]	file containing iptables-save output
	Optional parameters:
		source/destination ports (e.g. --dports, --source-port)
		source/destination addresses (e.g. -s, -d, --src-range)
		protocol(s) (e.g. -p, --protocols)
		
Limitations:
	- This tool currently only looks at the options specified in the
	  required and optional parameters. For instance, it ignores options
	  from most extension modules, such as matching TCP connections and 
	  filtering by MAC address. More options can be added by adding more
	  tuples to the algorithm.
	- This tool currently doesn't work with rules that don't jump to a 
	  target. For example, it doesn't work with rules that use -g or --goto
	  instead of -j or --jump
"""

################################################
#### iptables syntax and available options
################################################

#### Chains ####
# -A, --append
chains = ['-A', '--append']

#### targets ####
# -j, --jump
targets = ['-j', '--jump']

#### ports ####
# --destination-port, --dport, --sport, --source-port, --dports, --sports
# possible formats: 80   80,443  1000:1010   1:900,1000:10000
# TODO	ports can be negated with "!" ("! --dports 0:999")
dports = ['--destination-port', '--dport', '--dports']
sports = ['--sport', '--source-port', '--sports']

#### addresses ####
# -d, --destination, -dst, -s, --source, -src
# -possible formats: 1.1.1.0/24, 1.1.1.1, 1.1.1.0/255.255.255.0
# -src-range (-dst-range) 1.1.1.20-1.1.1.23
# TODO 	addresses can be negated with !
saddresses = ['-s', '--source', '-src', '--src-range']
daddresses = ['-d', '--destination', '-dst', '--dst-range']

#### protocols ####
# -p, --protocol
# can be: tcp, udp, udplite, icmp, imcpv6, esp, ah, sctp, mh, all
# can also use protocols found in /etc/protocols
protocols = ['-p', '--protocols']


######################################
### Functions
######################################

### Usage Statement
def usage():
    exit(usageStatement)


### parseRule
# returns a LIST containing the tuples derived from the rule
#	a list is used because a single rule might expand into several
# 
# rule - a string containing the iptable options to specify the rule
#	 For example: "-A INPUT -p ipencap -j DROP"
def parseRule(rule):
    rule = rule.rstrip('\r\n').split(" ")
    # min/max values for each tuple
    daddrMin = 0
    daddrMax = 4294967295
    saddrMin = 0
    saddrMax = 4294967295
    dportMin = 1
    dportMax = 65535
    sportMin = 1
    sportMax = 65535
    protoMin = 0
    protoMax = 255
    jump = 0  # default DROP (just incase a rule contains no target)
    rules = []  # stores all created rules, returned on exit

    # iterate over rule to extract ranges
    i = 0
    while i < len(rule):

        # ignore chain
        if any(j == rule[i] for j in chains):
            i += 2
            continue

        # check for daddress
        elif any(j == rule[i] for j in daddresses):
            i = i + 2
            daddr = rule[i - 1]
            # check syntax
            if '/' in daddr:  # subnet
                ip = IPv4Network(daddr, strict=False)
                daddrMin = int(ip.network_address)
                daddrMax = int(ip.broadcast_address)
            elif '-' in daddr:  # host range
                ips = daddr.split('-')
                daddrMin = int(IPv4Address(ips[0]))
                daddrMax = int(IPv4Address(ips[1]))
            else:  # single host
                ip = int(IPv4Address(daddr))
                if ip != 0:  # if not default route (entire IP range)
                    daddrMin = daddrMax = ip
            continue

        # check for saddress
        elif any(j == rule[i] for j in saddresses):
            i = i + 2
            saddr = rule[i - 1]
            # check syntax
            if '/' in saddr:  # subnet
                ip = IPv4Network(saddr, strict=False)
                saddrMin = int(ip.network_address)
                saddrMax = int(ip.broadcast_address)
            elif '-' in saddr:  # host range
                ips = saddr.split('-')
                saddrMin = int(IPv4Address(ips[0]))
                saddrMax = int(IPv4Address(ips[1]))
            else:  # single host
                ip = int(IPv4Address(saddr))
                if ip != 0:  # if not default route (entire IP range)
                    saddrMin = saddrMax = ip
            continue

        # check for protocol
        elif any(j == rule[i] for j in protocols):
            i = i + 2
            try:
                if rule[i - 1] == "all":
                    continue
                p = int(rule[i - 1])
            except:
                try:
                    p = getprotobyname(rule[i - 1])
                except Exception as e:
                    print("ERROR: " + str(e))
                    usage()
            protoMin = protoMax = p
            continue

        # check for dport
        elif any(j == rule[i] for j in dports):
            i = i + 2
            if ',' in rule[i - 1]:  # comma separated, create multiple rules
                ports = rule[i - 1].split(',')
                for port in ports:
                    newRule = rule[:]
                    newRule[i - 1] = port
                    rules.append(parseRule((" ".join(newRule)))[0])
                return rules  # <-- prevents an extra rule from being added at end of function
            elif ':' in rule[i - 1]:  # range of ports
                dportMin = int(rule[i - 1].split(':')[0])
                dportMax = int(rule[i - 1].split(':')[1])
            else:  # single port
                dportMin = dportMax = int(rule[i - 1])
            continue

        # check for sport
        elif any(j == rule[i] for j in sports):
            i = i + 2
            if ',' in rule[i - 1]:  # comma separated, create multiple rules
                ports = rule[i - 1].split(',')
                for port in ports:
                    newRule = rule[:]
                    newRule[i - 1] = port
                    rules.append(parseRule((" ".join(newRule)))[0])
                return rules  # <-- prevents an extra rule from being added at end of function
            elif ':' in rule[i - 1]:  # range of ports
                sportMin = int(rule[i - 1].split(':')[0])
                sportMax = int(rule[i - 1].split(':')[1])
            else:  # single port
                sportMin = sportMax = int(rule[i - 1])
            continue

        # check for target
        elif any(j == rule[i] for j in targets):
            i = i + 2
            target = rule[i - 1]
            if target.upper() == "DROP":
                jump = 0
            elif target.upper() == "ACCEPT":
                jump = 1
            elif target.upper() == "REJECT":
                jump = 2
            elif target.upper() == "QUEUE":
                jump = 3
            elif target.upper() == "RETURN":
                jump = 4
            continue

        return []  # ignore rules that contain unsupported fields

    rules.append(((saddrMin, saddrMax),  # src address range
                  (sportMin, sportMax),  # src port range
                  (daddrMin, daddrMax),  # dst address range
                  (dportMin, dportMax),  # dst port range
                  (protoMin, protoMax),  # protocol
                  jump))  # action type
    return rules


### extractRules
# given a file and a chain, it parses each line and adds rules that correspond to
# the given chain to the firewall verification object
#
# f - file pointer (created after opening the file)
# chain - name of the chain to look at
def extractRules(f, chain):
    defaultPolicy = ""
    for i in f:  # read each line in the file
        if i[0] == '-':  # line contains a rule
            if chain in i.split(' '):
                rules = parseRule(i)  # returns a list of rule tuples
                for r in rules:
                    fv.add(r)  # add rules to verifier
        elif i[0] == ':':  # line defines a chain
            if ":" + chain in i.split(' '):
                defaultPolicy = i.split(" ")[1]
                if defaultPolicy == 'ACCEPT':
                    defaultPolicy = 1
                else:
                    defaultPolicy = 0
    if defaultPolicy == "":
        print("ERROR: Can't find a default policy for '" + chain + "'")
        usage()
    # add default policy rule
    fv.add(((0, 4294967295),
            (1, 65535),
            (0, 4294967295),
            (1, 65535),
            (0, 255),
            defaultPolicy))


def main(args):
    ### parse command line arguments
    fileArgs = ['-file', '-infile']
    ruleFile = ""
    chain = ""
    targetPresent = False
    args = args[1:]  # cutoff head
    property_args = []  # arguments describing the property
    i = 0  # process all command line arguments
    while i < len(args):  # check for required parameters
        if any(j == args[i] for j in chains):  # check for chain
            chain = args[i + 1]
            property_args.append(args[i])
        elif any(j == args[i] for j in fileArgs):  # check for file
            ruleFile = args[i + 1]
            i += 1  # dont add file args to policy args
        elif any(j == args[i] for j in targets):  # check for target
            targetPresent = True
            property_args.append(args[i])
        else:
            property_args.append(args[i])
        i += 1
    if chain == "":
        print("ERROR: Cannot find chain.\nUse -A or --append to specify the chain.")
        usage()
    if ruleFile == "":
        print("ERROR: No rule file specified.\nUse -file or -infile to specify the rule file.")
        usage()
    if not targetPresent:
        print("ERROR: No target specified\nUse -j or --jump to specify the target")
        usage()

    if not path.exists(ruleFile):  # check if file exists
        print("ERROR: Cannot find the file " + ruleFile)
        usage()

    ### parse file, create tuples, and check for witness
    with open(ruleFile) as f:  # iptables-save > rules.txt
        extractRules(f, chain)  # build firewall from infile
        policy = parseRule(" ".join(property_args))
        for i in policy:  # looped to account for the possibility of multiple rules
            if not fv.verify(i):
                witness = fv.witness()
                src_ip = IPv4Address(witness[0]).exploded
                src_port = witness[1]
                dst_ip = IPv4Address(witness[2]).exploded
                dst_port = witness[3]
                protocol = witness[4]
                print("--> Property fails!\n"
                      "The following witness packet was found..\n"
                      "\tSource      - " + src_ip + ":" + str(src_port) + "\n",
                      "\tDestination - " + dst_ip + ":" + str(dst_port) + "\n",
                      "\tProtocol    - " + str(protocol))
                exit()
        print("--> Property passes!")


if __name__ == "__main__":
    # execute only if run as a script
    main(argv)
