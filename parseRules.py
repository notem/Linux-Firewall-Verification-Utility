#!/usr/bin/env python3

# date: 2018-04-09
# contributor(s):
#	Michael Rhodes, mjr2563@rit.edu
# description:
#	
# usage:
#


import firewall_verifier as fv
from ipaddress import IPv4Address,IPv4Network
from socket import getprotobyname
# from subprocess import check_output
from sys import argv,exit
from os import path


# TODO: Check if algorithm can handle more than 1/0 for the policy
#	clean up comments, create usage statement
#	print more information when a witness packet is found


#possible problems:
#	how should we handle rules with a goto [chain] instead of jump [target]?




################################################
#### iptables syntax and available options
################################################

#### Chains ####
# -A, --append
chains = ['-A','--append']

#### targets ####
# -j, --jump
targets = ['-j','--jump']

#### ports ####
# --destination-port, --dport, --sport, --source-port, --dports, --sports
# possible formats: 80   80,443  1000:1010   1:900,1000:10000
#	ports can be negated with "!" ("! --dports 0:999")
dports = ['--destination-port', '--dport', '--dports']
sports = ['--sport', '--source-port', '--sports']

#### addresses ####
# -d, --destination, -dst, -s, --source, -src
# -possible formats: 1.1.1.0/24, 1.1.1.1, 1.1.1.0/255.255.255.0
# -src-range (-dst-range) 1.1.1.20-1.1.1.23
# 	addresses can be negated with !
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
  exit(1)

### parseRule
# returns a LIST containing the tuples derived from the rule
#	a list is used because a single rule might expand into several
# assumes chain has already been checked
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
  rules = [] 		# stores all created rules, returned on exit
  
 # iterate of rule to extract ranges
  i = 0
  while i < len(rule):

   # check for daddress
    if any(j == rule[i] for j in daddresses):
      i = i + 2
      daddr = rule[i-1]
     # check syntax
      if ('/' in daddr): # subnet
         ip = IPv4Network(daddr,strict=False) 
         daddrMin = int(ip.network_address)
         daddrMax = int(ip.broadcast_address)
      elif ('-' in daddr): # host range
         ips = daddr.split('-')
         daddrMin = int(IPv4Address(ips[0]))
         daddrMax = int(IPv4Address(ips[1]))
      else: # single host
        ip = int(IPv4Address(daddr))
        if (ip != 0): # if not default route (entire IP range)
          daddrMin = daddrMax = ip
      continue

   # check for saddress
    if any(j == rule[i] for j in saddresses):
      i = i + 2
      saddr = rule[i-1]
     # check syntax
      if ('/' in saddr): # subnet
         ip = IPv4Network(saddr,strict=False) 
         saddrMin = int(ip.network_address)
         saddrMax = int(ip.broadcast_address)
      elif ('-' in saddr): # host range
        ips = daddr.split('-')
        saddrMin = int(IPv4Address(ips[0]))
        saddrMax = int(IPv4Address(ips[1]))
      else: # single host
        ip = int(IPv4Address(saddr))
        if (ip != 0): # if not default route (entire IP range)
          saddrMin = saddrMax = ip
      continue

   # check for protocol
    if any(j == rule[i] for j in protocols):
      i = i + 2
      try:
#        if (rule[i-1] == "all"): continue
#		-p all can be used to create rules but its omitted in iptables-save
        p = int(rule[i-1])
      except:
        p = getprotobyname(rule[i-1])
      protoMin = protoMax = p
      continue

   # check for dport
    if any(j == rule[i] for j in dports):
      i = i + 2
      if (',' in rule[i-1]):	# comma separated, create multiple rules
         ports = rule[i-1].split(',')
         for port in ports:
           newRule = rule[:]
           newRule[i-1] = port
           rules.append(parseRule((" ".join(newRule)))[0])
         return rules	#<-- prevents an extra rule from being added at end of function
      elif (':' in rule[i-1]):	# range of ports
        dportMin = int(rule[i-1].split(':')[0])
        dportMax = int(rule[i-1].split(':')[1])
      else:	# single port
        dportMin = dportMax = int(rule[i-1])
      continue

   # check for sport
    if any(j == rule[i] for j in sports):
      i = i + 2
      if (',' in rule[i-1]):	# comma separated, create multiple rules
         ports = rule[i-1].split(',')
         for port in ports:
           newRule = rule[:]
           newRule[i-1] = port
           rules.append(parseRule((" ".join(newRule)))[0])
         return rules	#<-- prevents an extra rule from being added at end of function
      elif (':' in rule[i-1]):	# range of ports
        sportMin = int(rule[i-1].split(':')[0])
        sportMax = int(rule[i-1].split(':')[1])
      else:	# single port
        sportMin = sportMax = int(rule[i-1])
      continue

   # check for target
    if any(j == rule[i] for j in targets):
      i = i + 2
      target = rule[i-1]
      if(target == "DROP"):
         target = 0
      elif (target == "ACCEPT"):
         target = 1
      elif(target == "Reject"):
         target = 2
      elif(target == "QUEUE"):
         target = 3
      elif(target == "RETURN"):
         target = 4
      continue

    i = i + 1
  rules.append(((saddrMin,saddrMax),(sportMin,sportMax),(daddrMin,daddrMax),(dportMin,dportMax),(protoMin,protoMax),target))
  return rules


### extractRules
# given a file and a chain, it parses each line and adds rules that correspond to
# the given chain to the firewall verification object
# f - file pointer
# chain - name of the chain to look at
def extractRules(f, chain):
  defaultPolicy = ""
  for i in f:	# read each line in the file
    if (i[0] == '-'): # line contains a rule
      if (chain in i.split(' ')):
        rules = parseRule(i)	# returns a list of rule tuples
        for r in rules:
          fv.add(r)		# add rules to verifier
          print("DEBUG: ",r)
    elif (i[0] == ':'): # line defines a chain
      if (":"+chain in i.split(' ')): 
        defaultPolicy = i.split(" ")[1] 
        if (defaultPolicy=='ACCEPT'): defaultPolicy = 1  
        else: defaultPolicy=0
  if (defaultPolicy == ""):
    print("Can't find a default policy for '"+chain+"'")
    usage()
  fv.add(((0,4294967295),(1,65535),(0,4294967295),(1,65535),(0,255),defaultPolicy))


### parse command line arguments
fileArgs = ['-file','-infile']
ruleFile = ""
chain = ""
targetPresent = False
argv = argv[1:]
for i in range(len(argv)):
  if (any(j == argv[i] for j in chains)):	# check for chain
    chain = argv[i+1]
  if (any(j == argv[i] for j in fileArgs)):	# check for file
    ruleFile = argv[i+1]
  if (any(j == argv[i] for j in targets)):	# check for target
    targetPresent = True
if (chain == ""):
  print("ERROR: Cannot find chain.\nUse -A or --append to specify the chain.")
  usage()
if (ruleFile == ""):
  print("ERROR: No rule file specified.\nUse -file or -infile to specify the rule file.")
  usage()
if (not targetPresent):
  print("ERROR: No target specified\nUse -j or --jump to specify the target")
  usage()

if (not path.exists(ruleFile)):			# check if file exists
  print("Cannot find the file : "+ruleFile)
  usage()

### parse file, create tuples, and check for witness
with open (ruleFile) as f: #iptables-save > rules.txt
  extractRules(f, chain)
  policy = parseRule(" ".join(argv))
  for i in policy: # looped to account for the possibility of multiple rules
    if (not fv.verify(i)):
      print ("--> Witness found:",fv.witness())
      exit()
  print("--> Property passes!")





