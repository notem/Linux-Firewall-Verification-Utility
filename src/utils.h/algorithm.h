/**
 * date: 2018-03-19
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

/** SIZE is the number of fields of a rule, the number here must
   match the number of for loops used when testing candidates */
#define SIZE ((uint32_t) 5)

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
 * the algorithm does projection in-place, modifying both arrays
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
uint32_t* least_witness(uint32_t* lo, uint32_t* hi, const uint32_t* va, uint32_t count);

#endif //IPTABLES_VERIFICATION_RULES_H
