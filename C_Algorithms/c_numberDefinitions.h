/**
 * Contains function typedefs used
 * for various number operations and
 * defines a few nearly universal
 * numerical functions.
 *
 */

#ifndef C_NUMBER_DEFINITIONS_H
#define C_NUMBER_DEFINITIONS_H

#ifdef __cplusplus
extern "C" {
#endif
	#include "cryptoCConstants.h"

    #include <stdio.h>
    #include <stdint.h>
	#include <stdlib.h>
	#include <string.h>

    /** @brief Operator function typedef
     *
     * This function typedef defines a function
     * which takes in two arrays which represent
     * numbers, preform some operation on the
     * pair and then output the result to a
     * third array.
     *
     * @param [in] uint32_t* Argument 1
     * @param [in] uint32_t* Argument 2
     * @param [out] uint32_t* Output
     * @param [in] uint16_t size
     * @return 1 if success, 0 if failed
     */
    typedef int (*operatorFunction)(const uint32_t*,const uint32_t*,uint32_t*,uint16_t);
    /** @brief Triple operator function typedef
     *
     * This function typedef defines a function
     * which takes in three arrays which represent
     * numbers, preform some operation on the
     * triple and then output the result to a
     * fourth array.
     *
     * @param [in] uint32_t* Argument 1
     * @param [in] uint32_t* Argument 2
     * @param [in] uint32_t* Argument 3
     * @param [out] uint32_t* Output
     * @param [in] uint16_t size
     * @return 1 if success, 0 if failed
     */
	typedef int (*tripleCalculation)(const uint32_t*,const uint32_t*,const uint32_t*,uint32_t*,uint16_t);
    /** @brief Shift operator function typedef
     *
     * This function typedef defines a function
     * which takes in an array representing a
     * number, shifts it the provided number of
     * bits and outputs the result into
     * the second array.
     *
     * @param [in] uint32_t* Argument 1
     * @param [in] uint16_t Bits to shift
     * @param [out] uint32_t* Output
     * @param [in] uint16_t size
     * @return 1 if success, 0 if failed
     */
    typedef int (*shiftFunction)(const uint32_t*,uint16_t,uint32_t*,uint16_t);
    /** @brief Comparison function typedef
     *
     * This function typedef defines a function
     * which takes in two arrays which represent
     * numbers and then compares them.
     *
     * @param [in] uint32_t* Argument 1
     * @param [in] uint32_t* Argument 2
     * @param [in] uint16_t size
     * @return -1 if 1<2, 0 if 1==2, 1 if 1>2
     */
    typedef int (*compareFunction)(const uint32_t*,const uint32_t*,uint16_t);

    /** @brief Number type function structure
     *
     * This structure contains a series of
     * meaningful function pointers which
     * define functions required to meaningfully
     * define a numerical system.
     */
    struct numberType
    {
        /** @brief ID integer of the number type
         */
        int typeID;
        /** @brief Name of the number type
         */
        const char* name;

        /** @brief Pointer to comparison function
         */
        compareFunction compare;

        /** @brief Pointer to addition function
         */
        operatorFunction addition;
        /** @brief Pointer to subtraction function
         */
        operatorFunction subtraction;

        /** @brief Pointer to right-shift function
         */
        shiftFunction rightShift;
        /** @brief Pointer to left-shift function
         */
        shiftFunction leftShift;

        /** @brief Pointer to multiplication function
         */
        operatorFunction multiplication;
        /** @brief Pointer to division function
         */
        operatorFunction division;
        /** @brief Pointer to modulo function
         */
		operatorFunction modulo;

        /** @brief Pointer to exponentiation function
         */
		operatorFunction exponentiation;
        /** @brief Pointer to modulo exponentiation function
         */
		tripleCalculation moduloExponentiation;

        /** @brief Pointer to greatest common denominator function
         */
		operatorFunction gcd;
        /** @brief Pointer to modulo inverse function
         */
		operatorFunction modInverse;
    };

    /** @brief Construct a NULL number
     *
     * This function will return a numberType
     * pointer defining the function pointers
     * for a NULL number.  Note that the resulting
     * pointer points to a structure which is static
     * to the c_numberDefinitions.c file.
     *
     * @return Pointer to numberType of type NULL
     */
    struct numberType* buildNullNumberType();

    /** @brief Standard comparision
     *
     * This function takes in two arrays
     * which represent numbers and then compares them.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [in] length Number of uint32_t in the arrays
     * @return -1 if 1<2, 0 if 1==2, 1 if 1>2
     */
    int standardCompare(const uint32_t* src1, const uint32_t* src2, uint16_t length);
    /** @brief Right shift
     *
     * Shifts the bits in src1 in the right direction
     * src2 number of bits.  Output the result in dest.
     * Note that dest and src1 should be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Bits to shift
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int standardRightShift(const uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length);
    /** @brief Left shift
     *
     * Shifts the bits in src1 in the left direction
     * src2 number of bits.  Output the result in dest.
     * Note that dest and src1 should be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Bits to shift
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int standardLeftShift(const uint32_t* src1, uint16_t src2, uint32_t* dest, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif