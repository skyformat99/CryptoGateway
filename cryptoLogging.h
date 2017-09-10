/**
 * This file contains declarations which are used
 * for logging within the crypto namespace.
 *
 */

#ifndef CRYPTO_LOGGING_H
#define CRYPTO_LOGGING_H

#include <iostream>
#include "Datastructures/smartPointer.h"

namespace crypto
{

    /** @brief Deprecated logging flag
     *
     * Old logging flag.  Deprecated
     * in the new CryptoGateway files.
     * This has been replaced by
     * the logging system outlined
     * in this file.
     */
	extern bool global_logging;
	/** @brief Standard out pointer for crypto namespace
	 *
	 * This std::ostream is used as standard out
	 * for the crypto namespace.  This pointer can be
	 * swapped out to programmatically redirect standard out for
	 * the crypto namespace.
	 */
	extern os::smart_ptr<std::ostream> cryptoout_ptr;
	/** @brief Standard error pointer for crypto namespace
	 *
	 * This std::ostream is used as standard error
	 * for the crypto namespace.  This pointer can be
	 * swapped out to programmatically redirect standard error for
	 * the crypto namespace.
	 */
    extern os::smart_ptr<std::ostream> cryptoerr_ptr;

    /** @brief Standard out object for crypto namespace
	 *
	 * #define statements allow the user to call this
	 * function with "crypto::cryptoout."  Logging is achieved
	 * by using "crypto::cryptoout" as one would use "std::cout."
	 */
	std::ostream& cryptoout_func();
	/** @brief Standard error object for crypto namespace
	 *
	 * #define statements allow the user to call this
	 * function with "crypto::cryptoerr."  Logging is achieved
	 * by using "crypto::cryptoerr" as one would use "std::cerr."
	 */
	std::ostream& cryptoerr_func();
}
#ifndef cryptoout
#define cryptoout cryptoout_func()
#endif
#ifndef cryptoerr
#define cryptoerr cryptoerr_func()
#endif

#endif