/**
 * date: 2018-04-07
 * contributors(s):
 *   Nate Mathews, njm3308@rit.edu
 * description:
 *   header file for the algorithm component of the project
 *   exposes API for the least witness algorithm both with
 *   and without slicing
 */

#ifndef IPTABLES_VERIFICATION_RULES_H
#define IPTABLES_VERIFICATION_RULES_H

#include <stdint.h>
#include <stdbool.h>

/** SIZE is the number of fields of a rule, the number here must
   match the number of for loops used when testing candidates */
#define SIZE ((uint32_t) 5)

/**
 * wrapper to allow for easier toggling of usage of slices
 * @param lo     lower bounds for firewall rules
 *               the first FIVE elements specify the property fields
 * @param hi     upper bounds of firewall rules
 *               the first FIVE elements specify the property fields
 * @param va     action value for each rule
 *               the first ONE element specifies the property action
 * @param count  number of property & firewall rules supplied
 * @return a witness vector or NULL, if not NULL caller is responsible for freeing witness
 * @param slicing true to indicate that the with_slicing function should
 *               be used, otherwise use least_witness
 * @return
 */
uint32_t* find_witness(const uint32_t* lo, const uint32_t* hi, const uint32_t* va, uint32_t count, bool slicing);

/**
 * divides the firewall into firewall 'slices' and projects
 * rules in a slice over the final disagreeing rule
 *
 * this function wraps around the least_witness algorithm
 *
 * @param lo     lower bounds for firewall rules
 *               the first FIVE elements specify the property fields
 * @param hi     upper bounds of firewall rules
 *               the first FIVE elements specify the property fields
 * @param va     action value for each rule
 *               the first ONE element specifies the property action
 * @param count  number of property & firewall rules supplied
 * @return a witness vector or NULL, if not NULL caller is responsible for freeing witness
 */
uint32_t* with_slicing(const uint32_t* lo, const uint32_t* hi, const uint32_t* va, uint32_t count);

/**
 * projects firewall rules over the property, generates test points,
 * and evaluates candidate witness packets
 *
 * @param lo     lower bounds for firewall rules
 *               the first FIVE elements specify the property fields
 * @param hi     upper bounds of firewall rules
 *               the first FIVE elements specify the property fields
 * @param va     action value for each rule
 *               the first ONE element specifies the property action
 * @param count  number of property & firewall rules supplied
 * @return a witness vector or NULL, if not NULL caller is responsible for freeing witness
 */
uint32_t* without_slicing(const uint32_t *lo, const uint32_t *hi, const uint32_t *va, uint32_t count);


/**
 * forms cartesian product candidate packets and compare to firewall rule list
 * @param lo      lower bounds for firewall rules
 *                the first FIVE elements specify the property fields
 * @param hi      upper bounds of firewall rules
 *                the first FIVE elements specify the property fields
 * @param va      action value for each rule
 *                the first ONE element specifies the property action
 * @param count   number of property & firewall rules supplied
 * @param set     set (as an array SIZE*count) of unique possible endpoints
 * @param indices the number of endpoints for each field (an array of SIZE)
 * @return a witness vector or NULL, if not NULL caller is responsible for freeing witness
 */
uint32_t* test_candidates(const uint32_t *lo, const uint32_t *hi, const uint32_t *va,
                          uint32_t count, const uint32_t *set, const uint32_t *indices,
                          const uint32_t *mask);

#endif //IPTABLES_VERIFICATION_RULES_H
