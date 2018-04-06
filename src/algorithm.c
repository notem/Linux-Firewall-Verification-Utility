/**
 * date: 2018-03-19
 * contributors(s):
 *   Nate Mathews, njm3308@rit.edu
 * description:
 *   implementation of least witness algorithm
 *   some additional optimization could be done, however the
 *   current state of the algorithm is probably adequate
 */

#include <string.h>
#include <malloc.h>
#include <stdlib.h>
#include "algorithm.h"

// wrapper to easily switch between running the algorithm with|without slicing
uint32_t* find_witness(const uint32_t *lo, const uint32_t *hi, const uint32_t *va, uint32_t count, bool slicing)
{
    if (slicing)
        return with_slicing(lo, hi, va, count);
    else
        return least_witness(lo, hi, va, count);
}

// with slicing wrapper
uint32_t* with_slicing(const uint32_t *lo, const uint32_t *hi, const uint32_t *va, uint32_t count)
{
    /* buffers to hold slice information */
    uint32_t *lo_s = malloc(sizeof(*lo_s)*SIZE*count), // lower-bounds of firewall rules
             *hi_s = malloc(sizeof(*hi_s)*SIZE*count), // upper-bounds of firewall rules
             *va_s = malloc(sizeof(*va_s)*SIZE*count); // action values (ALLOW,DENY,etc)
    /* copy property to first 'rule' slot */
    va_s[0] = va[0];
    for (int k=0; k<SIZE; k++)
    {
        lo_s[k] = lo[k];
        hi_s[k] = hi[k];
    }
    /* form and test slices */
    uint32_t pos = 0, count_s;
    while (pos+1 < count)
    {
        count_s = 1; // count of rules in slice
        /* loop through rules and build slice */
        for (uint32_t i=1; i<count; i++)
        {
            /* if agreeing rule, add to slice  */
            if (va[i] == va[0])
            {
                va_s[count_s] = va[i];
                for (int k=0; k<SIZE; k++)
                {
                    lo_s[SIZE*count_s+k] = lo[SIZE*i+k];
                    hi_s[SIZE*count_s+k] = hi[SIZE*i+k];
                }
                count_s++;
            }

            /* if disagree rule not yet reached, add to slice,
             * project slice, run least_witness */
            if (va[i] != va[0] && pos < i)
            {
                // add slice's disagree rule
                for (int k=0; k<SIZE; k++)
                {
                    lo_s[SIZE*count_s+k] = lo[SIZE*i+k];
                    hi_s[SIZE*count_s+k] = hi[SIZE*i+k];
                    va_s[count_s] = va[i];
                }
                count_s++;

                /* project agreeing rules over disagree rule */
                for (uint32_t l=1; l<count_s; l++)
                {
                    for (uint32_t j=0; j<SIZE; j++)
                    {
                        uint32_t z = (l*SIZE)+j;
                        uint32_t k = ((count_s-1)*SIZE)+j;
                        hi_s[z] = (hi_s[z] < hi_s[k]) ? hi_s[z] : hi_s[k];
                        lo_s[z] = (lo_s[z] < lo_s[k]) ? lo_s[k] : lo_s[z];
                    }
                }

                /* apply least witness algorithm on slice */
                uint32_t* candidate = least_witness(lo_s, hi_s, va_s, count_s);
                if (candidate != NULL)
                {   // return candidate if found
                    free(lo_s);
                    free(hi_s);
                    free(va_s);
                    return candidate;
                }
                pos = i;
                break;
            }

            // set max position reached
            if (i>pos)
                pos = i;
        }
    }
    free(lo_s);
    free(hi_s);
    free(va_s);
    return NULL;
}

// without slicing
uint32_t* least_witness(const uint32_t* lo, const uint32_t* hi, const uint32_t *va, uint32_t count)
{
    /* initialize and zero arrays to represent the set of end-points */
    uint32_t *set = malloc(sizeof(*set)*SIZE*count); // set of possible end-points (fields indexed by n*count)
    uint32_t *indices = malloc(sizeof(*set)*SIZE);   // size of set for each field
    for (int i=0; i<SIZE; i++) indices[i] = 0; // zero-out indices counters

    /* nested for loop first projects the current field onto the property
     * then determines the end-point to add to the end point set */
    for (int i=1; i<count; i++) // for each rule
    {
        uint32_t p = i*SIZE; // offset of rule start
        for (int k=0; k<SIZE; k++)  // for each field in rule
        {   /* do projection (save points in temporary elements) */
            uint32_t z = p+k;   // current position
            uint32_t hi_tmp = (hi[z] < hi[k]) ? hi[z] : hi[k]; // set hi to min
            uint32_t lo_tmp = (lo[z] < lo[k]) ? lo[k] : lo[z]; // set lo to max

            /* calculate end-point */
            uint32_t endp, unique=1;
            if (va[i] == va[0])
                endp = hi_tmp+1;
            else
                endp = lo_tmp;

            // only add to set if end-point is within the property range
            if (endp <= hi[k] && endp >= lo[k])
            {
                // check if value already exists in set
                for (int j=0; j<indices[k]; j++)
                {
                    if (set[k*count+j] == endp)
                    {
                        unique = 0;
                        break;
                    }
                }
                if (unique) // add to set if unique
                    set[k*count+indices[k]++] = endp;
            }
        }
    }
    /* test candidate witnesses */
    uint32_t* candidate = malloc(SIZE * sizeof(uint32_t));
    for (int k1=0; k1<indices[0]; k1++)
    {
        for (int k2=0; k2<indices[1]; k2++)
        {
            for (int k3=0; k3<indices[2]; k3++)
            {
                for (int k4=0; k4<indices[3]; k4++)
                {
                    for (int k5=0; k5<indices[4]; k5++)
                    {   // form a unique witness
                        candidate[0] = set[k1];
                        candidate[1] = set[count+k2];
                        candidate[2] = set[2*count+k2];
                        candidate[3] = set[3*count+k2];
                        candidate[4] = set[4*count+k2];
                        for (int i=1; i<count; i++) // compare witness to each firewall
                        {   // determine if candidate will hit the rule
                            int hit = 1; // assume candidate will hit
                            for (int j=0; j<SIZE; j++)
                            {   // search for fields which miss
                                if (candidate[j] > hi[i*SIZE+j]     // if candidate greater than max bound
                                    || candidate[j] < lo[i*SIZE+j]) // or less than lower bound
                                {   // candidate witness did not hit the rule
                                    hit = 0;
                                    break;
                                }
                            }
                            if (hit)
                            {   // if the matched rule conflicts, witness has been found
                                if (va[0] != va[i])
                                {
                                    free(set);
                                    free(indices);
                                    return candidate;
                                }
                                break; // otherwise, move to next candidate
                            }
                        }
                    }
                }
            }
        }
    }
    // no witness found
    free(candidate);
    free(set);
    free(indices);
    return NULL;
}
