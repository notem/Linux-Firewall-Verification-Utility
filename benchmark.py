#!/usr/bin/python3
#   simple script to benchmark the algorithm's performance
#
import firewall_verifier as fv
import random as r
from timeit import default_timer as timer


def generate_firewall(count):
    for i in range(0, count):
        tup1 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup2 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup3 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup4 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup5 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        rule = (tup1, tup2, tup3, tup4, tup5, r.randint(0, 1))
        fv.add(rule)
    return


def main():
    r.seed()
    print("\nBeginning firewall generation...", end="")
    start = timer()
    generate_firewall(count=2*(10**4))  # firewall of 20,000 rules
    end = timer()
    print(" completed in ", end-start, "seconds")

    # dry run
    prop = ((0, 0), (0, 0), (0, 0), (0, 0), (0, 0), 0)
    print("\nBeginning dry run test...", end="")
    start = timer()
    fv.verify(prop)
    end = timer()
    print(" completed in ", end-start, "seconds")

    # try random properties and compute an average
    trials = 30
    print("\nRunning (", trials, ") trials...")
    times = []
    for i in range(0, trials):
        tup1 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup2 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup3 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup4 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        tup5 = (r.randint(1, 1 << 32), r.randint(1, 1 << 32))
        prop = (tup1, tup2, tup3, tup4, tup5, r.randint(0, 1))

        print("\t Beginning trial", i, "...", end="")
        start = timer()
        fv.verify(prop)
        end = timer()
        times.append(end-start)
        print(" completed in ", times[i], "seconds")

    avg = 0
    for time in times:
        avg += time
    avg /= trials
    print("\nAverage run completed in ", avg, "seconds")
    return


if __name__ == '__main__':
    main()
