/**
 * date: 2018-04-07
 * contributors(s):
 *   Nate Mathews, njm3308@rit.edu
 * description:
 *   implementation of least witness + slicing algorithm
 *   some additional optimization could be done (use hashset rather than naive set),
 *   however the current state of the algorithm is probably adequate
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
        return without_slicing(lo, hi, va, count);
}

// test with slicing
uint32_t* with_slicing(const uint32_t *lo, const uint32_t *hi, const uint32_t *va, uint32_t count)
{
    /* copy original values into temporary buffer */
    uint32_t *lo_n = malloc(sizeof(*lo_n)*SIZE*count), // lower-bounds of firewall rules
            *hi_n = malloc(sizeof(*hi_n)*SIZE*count);  // upper-bounds of firewall rules
    memcpy(lo_n, lo, sizeof(*lo_n)*SIZE*count);
    memcpy(hi_n, hi, sizeof(*hi_n)*SIZE*count);

    /* over-sized buffers to hold slice information */
    uint32_t *lo_s = malloc(sizeof(*lo_s)*SIZE*count), // lower-bounds of slice rules
             *hi_s = malloc(sizeof(*hi_s)*SIZE*count), // upper-bounds of slice rules
             *va_s = malloc(sizeof(*va_s)*SIZE*count); // action values (ALLOW,DENY,etc)

    /* buffers to hold end point set information */
    uint32_t *set = malloc(sizeof(*set)*SIZE*count); // set of possible end-points (fields indexed by n*count)
    uint32_t *indices = malloc(sizeof(*set)*SIZE);   // size of set for each field

    /* witness array to be return */
    uint32_t* witness = NULL;

    /* copy property to first 'rule' slot */
    va_s[0] = va[0];
    for (int k=0; k<SIZE; k++)
    {
        lo_s[k] = lo[k];
        hi_s[k] = hi[k];
    }

    /* project over rule */
    for (int i=1; i<count; i++) // for each rule
    {
        uint32_t p = i * SIZE; // offset of rule start
        for (int k = 0; k < SIZE; k++)  // for each field in rule
        {   /* do projection (save points in temporary elements) */
            uint32_t z = p + k;   // current position
            hi_n[z] = (hi[z] < hi[k]) ? hi[z] : hi[k]; // set hi to min
            lo_n[z] = (lo[z] < lo[k]) ? lo[k] : lo[z]; // set lo to max
        }
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
                    lo_s[SIZE*count_s+k] = lo_n[SIZE*i+k];
                    hi_s[SIZE*count_s+k] = hi_n[SIZE*i+k];
                }
                count_s++;
            }

            /* if next disagree rule has been reached -> do
             * add to slice, project slice, do cartesian product testing*/
            if (va[i] != va[0] && i > pos)
            {
                /* initialize and zero arrays to represent the set of end-points */
                for (int p=0; p<SIZE; p++) indices[p] = 0; // zero-out indices counters

                // add slice's disagree rule
                va_s[count_s] = va[i];
                for (int k=0; k<SIZE; k++)
                {
                    lo_s[SIZE*count_s+k] = lo_n[SIZE*i+k];
                    hi_s[SIZE*count_s+k] = hi_n[SIZE*i+k];
                }
                count_s++;

                /* do projection and end point generation*/
                for (uint32_t l=1; l<count_s; l++) // for each rule in slice
                {
                    for (uint32_t j=0; j<SIZE; j++) // for each field
                    {
                        /* calculate end-point */
                        uint32_t k = ((count_s-1)*SIZE)+j;
                        uint32_t z = (l*SIZE)+j;
                        uint32_t endp, unique=1;
                        // if not last rule, project and take end point
                        if (l!=count_s-1)
                        {
                            hi_s[z] = (hi_s[z] < hi_s[k]) ? hi_s[z] : hi_s[k];
                            lo_s[z] = (lo_s[z] < lo_s[k]) ? lo_s[k] : lo_s[z];
                            endp = hi_s[z]+1;
                        }
                        else // if last rule, skip projection
                        {
                            endp = lo_s[k];
                        }

                        // only add to set if end-point is within the property range
                        if (endp <= hi[j] && endp >= lo[j])
                        {   // check if value already exists in set
                            for (int o=0; o<indices[j]; o++)
                            {
                                if (set[j*count_s+o] == endp)
                                {
                                    unique = 0;
                                    break;
                                }
                            }
                            if (unique) // add to set if unique
                            {
                                set[j*count_s+indices[j]] = endp;
                                indices[j] += 1;
                            }
                        }
                    }
                }

                /* apply least witness algorithm on slice */
                witness = test_candidates(lo_s, hi_s, va_s, count_s, set, indices);
                if (witness != NULL) goto end;

                // set new max pos and
                // restart slice-building loop
                pos = i;
                break;
            }
            // set max position reached
            if (i>pos) pos = i;
        }
    }

end:
    free(set);
    free(indices);
    free(lo_n);
    free(hi_n);
    free(lo_s);
    free(hi_s);
    free(va_s);
    return witness;
}

// test without slicing
uint32_t* without_slicing(const uint32_t *lo, const uint32_t *hi, const uint32_t *va, uint32_t count)
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
                {
                    set[k*count+indices[k]] = endp;
                    indices[k] += 1;
                }
            }
        }
    }
    /* test candidate witnesses */
    uint32_t* witness = test_candidates(lo, hi, va, count, set, indices);
    free(set);
    free(indices);
    return witness;
}

// cartesian product and testing
uint32_t* test_candidates(const uint32_t *lo, const uint32_t *hi, const uint32_t *va,
                          uint32_t count, const uint32_t *set, const uint32_t *indices)
{
    uint32_t* candidate = malloc(SIZE * sizeof(*candidate));
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
                        candidate[2] = set[2*count+k3];
                        candidate[3] = set[3*count+k4];
                        candidate[4] = set[4*count+k5];
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
                                    return candidate;
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
    return NULL;
}
