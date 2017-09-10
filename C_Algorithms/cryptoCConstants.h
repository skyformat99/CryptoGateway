/**
 * Declares a number of constants needed
 * by both the C numerical algorithms
 * and by C++ number classes.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_C_CONSTANTS_H
#define CRYPTO_C_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

///@endcond

/** @brief Default number ID
 *
 * This constant is 0.  It represents an
 * untyped number.
 */
extern const int crypto_numbertype_default;
/** @brief Base-10 number ID
 *
 * This constant is 1.  It represents a
 * number of type base-10, or standard
 * integer.
 */
extern const int crypto_numbertype_base10;

/** @brief Default number marker
 *
 * This constant is "NULL Type".  It represents an
 * untyped number.
 */
extern const char* crypto_numbername_default;
/** @brief Base-10 number marker
 *
 * This constant is "Base 10 Type".
 * It represents a number of type
 * base-10, or standard integer.
 */
extern const char* crypto_numbername_base10;

///@cond INTERAL

#ifdef __cplusplus
}
#endif

#endif

///@endcond