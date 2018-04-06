/**
 * date: 2018-03-13
 * contributors(s):
 *   Nate Mathews, njm3308@rit.edu
 * description:
 *   tests a toy firewall against two properties using the least witness/
 *   probing algorithm with slicing
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "algorithm.h"

int main(int argc, char* argv[])
{
    uint32_t lo[5*6], hi[5*6], va[6], *witness;

    /* test 1 property */
    lo[0] = 23; lo[1] = 73; lo[2] = 0; lo[3] = 0; lo[4] = 0;
    hi[0] = 87; hi[1] = 177; hi[2] = 0; hi[3] = 0; hi[4] = 0; va[0] = 0; // ((23,87),(73,177)) -> 0

    /* firewall for testing */
    lo[5] = 10;   lo[6] = 90;   lo[7] = 0;  lo[8] = 0;  lo[9] = 0;  // rule 1
    hi[5] = 110;  hi[6] = 190;  hi[7] = 0;  hi[8] = 0;  hi[9] = 0;  va[1] = 0; // ((10,110),(90,190)) -> 0
    lo[10] = 20;  lo[11] = 80;  lo[12] = 0; lo[13] = 0; lo[14] = 0; // rule 2
    hi[10] = 120; hi[11] = 180; hi[12] = 0; hi[13] = 0; hi[14] = 0; va[2] = 1; // ((20,120),(80,180)) -> 1
    lo[15] = 30;  lo[16] = 70;  lo[17] = 0; lo[18] = 0; lo[19] = 0; // rule 3
    hi[15] = 130; hi[16] = 170; hi[17] = 0; hi[18] = 0; hi[19] = 0; va[3] = 0; // ((30,130),(70,170)) -> 0
    lo[20] = 40;  lo[21] = 60;  lo[22] = 0; lo[23] = 0; lo[24] = 0; // rule 4
    hi[20] = 140; hi[21] = 160; hi[22] = 0; hi[23] = 0; hi[24] = 0; va[4] = 1; // ((40,140),(60,160)) -> 1
    lo[25] = 1;   lo[26] = 1;   lo[27] = 0; lo[28] = 0; lo[29] = 0; // rule 5
    hi[25] = 200; hi[26] = 200; hi[27] = 0; hi[28] = 0; hi[29] = 0; va[5] = 0; // ((1,200),(1,200)) -> 0

    // find a witness
    witness = find_witness(lo, hi, va, 6, true);
    if (witness == NULL) printf("test 1) no witness found!\n");
    else printf("test 1) witness (%u, %u, %u, %u, %u) found!\n",
                witness[0], witness[1], witness[2], witness[3], witness[4]);

    /* test 2 property */
    lo[0] = 33; lo[1] = 75; lo[2] = 0; lo[3] = 0; lo[4] = 0;
    hi[0] = 87; hi[1] = 79; hi[2] = 0; hi[3] = 0; hi[4] = 0; va[0] = 0; // ((33,87),(75,79)) -> 0

    // no witness should be found
    witness = find_witness(lo, hi, va, 6, true);
    if (witness == NULL) printf("test 2) no witness found!\n");
    else printf("test 2) witness (%u, %u, %u, %u, %u) found!\n",
                witness[0], witness[1], witness[2], witness[3], witness[4]);
}
