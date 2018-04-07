#!/usr/bin/python3
#   simple script to benchmark the algorithm's performance
#
import firewall_verifier as fv
import random as r
from timeit import default_timer as timer

# tweak-able parameters
trials = 30
rules = 10**5


# randomly generate a 2-tuple, representing the range of the field
def generate_tuple():
    lo = r.randint(1, 1 << 32)
    hi = r.randint(lo, 1 << 32)
    tup = (lo, hi)
    return tup


# generate a tuple representing a firewall rule
def generate_rule():
    tup1 = generate_tuple()
    tup2 = generate_tuple()
    tup3 = generate_tuple()
    tup4 = generate_tuple()
    tup5 = generate_tuple()
    rule = (tup1, tup2, tup3, tup4, tup5, r.randint(0, 1))
    return rule


# generate and add rules to the firewall
def generate_firewall(count):
    for i in range(0, count):
        rule = generate_rule()
        fv.add(rule)
    return


# run the benchmarking routine
def main():
    r.seed()
    print("\n[firewall generation]: ", end="")
    start = timer()
    generate_firewall(count=rules)
    end = timer()
    print(end-start, "seconds")

    # dry run (no cartesian combinations generated)
    prop = ((0, 0), (0, 0), (0, 0), (0, 0), (0, 0), 0)
    print("\n[dry run]: ", end="")
    start = timer()
    fv.verify(prop)
    end = timer()
    print(end-start, "seconds")

    # try random properties and compute an average
    print("\n[trials]: ")
    times = []
    for i in range(0, trials):
        prop = generate_rule()
        print("\t[", i+1, "]: ", end="")
        start = timer()
        fv.verify(prop)
        end = timer()
        times.append(end-start)
        print(times[i], "seconds")

    avg = 0
    for time in times:
        avg += time
    avg /= trials
    print("\n[average]: ", avg, "seconds")
    return


if __name__ == '__main__':
    main()
