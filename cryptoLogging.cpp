/**
 * This file contains global functions and
 * variables used for logging in the crypto namespace.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_LOGGING_CPP
#define CRYPTO_LOGGING_CPP

#include "cryptoLogging.h"

//OS Logger Streams
bool crypto::global_logging = false;
os::smart_ptr<std::ostream> crypto::cryptoout_ptr = &(std::cout);
os::smart_ptr<std::ostream> crypto::cryptoerr_ptr = &(std::cerr);

std::ostream& crypto::cryptoout_func() {return *crypto::cryptoout_ptr;}
std::ostream& crypto::cryptoerr_func() {return *crypto::cryptoerr_ptr;}

#endif

///@endcond