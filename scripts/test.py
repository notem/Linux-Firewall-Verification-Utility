#!/usr/bin/env python3
#
# example usage of firewall_verifier
#   module functions:
#       add(rule)    -> number
#       verify(prop) -> bool
#       witness()    -> 5tuple
#       clear()      -> number
#       size()       -> number
#
import firewall_verifier as fv

# firewall rules are tuples composed of five 2-tuples and 0 integer
rule1 = ((10, 110), (90, 190), (0, 0), (0, 0), (0, 0), 0)   # ((10,110),(90,190)) -> 0
rule2 = ((20, 120), (80, 180), (0, 0), (0, 0), (0, 0), 1)   # ((20,120),(80,180)) -> 1
rule3 = ((30, 130), (70, 170), (0, 0), (0, 0), (0, 0), 0)   # ((30,130),(70,170)) -> 0
rule4 = ((40, 140), (60, 160), (0, 0), (0, 0), (0, 0), 1)   # ((40,140),(60,160)) -> 1
rule5 = ((1, 200), (1, 200), (0, 0), (0, 0), (0, 0), 0)     # ((1,200),(1,200)) -> 0
print("Test Firewall")
print("->", rule1)
print("->", rule2)
print("->", rule3)
print("->", rule4)
print("->", rule5)

# build firewall
fv.add(rule1)
fv.add(rule2)
fv.add(rule3)
fv.add(rule4)
fv.add(rule5)

# some property for testing (same form as firewall rules)
property1 = ((23, 87), (73, 177), (0, 0), (0, 0), (0, 0), 0)
property2 = ((33, 87), (75, 79), (0, 0), (0, 0), (0, 0), 0)

# property verify should fail
print("\nTest 1:", property1)
if fv.verify(property1):
    print("-> Property passes!")
else:
    print("-> Witness found:", fv.witness())

# property verify should pass
print("\nTest 2:", property2)
if fv.verify(property2):
    print("-> Property passes!")
else:
    print("-> Witness found:", fv.witness())

# use clear to start building a new firewall
size = fv.clear()
