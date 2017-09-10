/**
 * Contains functions which
 * define a base-10 integer.
 * There functions are bound
 * to a number type.
 *
 */

#ifndef C_BASE_TEN_H
#define C_BASE_TEN_H

#include "c_numberDefinitions.h"

#ifdef __cplusplus
extern "C" {
#endif
	#include <time.h>

	/** @brief Construct a base-10 number
     *
     * This function will return a numberType
     * pointer defining the function pointers
     * for a base-10 number.  Note that the resulting
     * pointer points to a structure which is static
     * to the c_BaseTen.c file.
     *
     * @return Pointer to numberType of type base-10
     */
    struct numberType* buildBaseTenType();

    /** @brief Base-10 addition
     *
     * This function takes in two arrays which
     * represent base-10 numbers, preforms src1+src2
     * on the pair and then output the result to
     * dest.  Note that all three arrays must
     * be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int base10Addition(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
    /** @brief Base-10 subtraction
     *
     * This function takes in two arrays which
     * represent base-10 numbers, preforms src1-src2
     * on the pair and then output the result to
     * dest.  Note that all three arrays must
     * be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int base10Subtraction(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);

    /** @brief Base-10 multiplication
     *
     * This function takes in two arrays which
     * represent base-10 numbers, preforms src1*src2
     * on the pair and then output the result to
     * dest.  Note that all three arrays must
     * be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int base10Multiplication(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
    /** @brief Base-10 division
     *
     * This function takes in two arrays which
     * represent base-10 numbers, preforms src1/src2
     * on the pair and then output the result to
     * dest.  Note that all three arrays must
     * be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int base10Division(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
    /** @brief Base-10 modulo
     *
     * This function takes in two arrays which
     * represent base-10 numbers, preforms src1%src2
     * on the pair and then output the result to
     * dest.  Note that all three arrays must
     * be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
    int base10Modulo(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);

    /** @brief Base-10 exponentiation
     *
     * This function takes in two arrays which
     * represent base-10 numbers, preforms src1+src2
     * on the pair and then output the result to
     * dest.  Note that all three arrays must
     * be the same size.
     *
     * @param [in] src1 Argument 1
     * @param [in] src2 Argument 2
     * @param [out] dest Output
     * @param [in] length Number of uint32_t in the arrays
     * @return 1 if success, 0 if failed
     */
	int base10Exponentiation(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
	int base10ModuloExponentiation(const uint32_t* src1, const uint32_t* src2, const uint32_t* src3, uint32_t* dest, uint16_t length);

	int base10GCD(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);
	int base10ModInverse(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length);

	int primeTest(const uint32_t* src1, uint16_t test_iteration, uint16_t length);

#ifdef __cplusplus
}
#endif

#endif