/**
 * This file contains all of the
 * headers in the CryptoGateway
 * library.  Project which depend
 * on the CryptoGateway library
 * need only include this file.
 **/

#ifndef CRYPTOGATEWAY_H
#define CRYPTOGATEWAY_H

namespace crypto
{
	/** @brief Deprecated logging flag
	 */
	extern bool global_logging;
}

#include "cryptoLogging.h"
#include "RC4_Hash.h"

#include "binaryEncryption.h"
#include "XMLEncryption.h"

#include "streamPackage.h"

#include "cryptoPublicKey.h"
#include "keyBank.h"
#include "user.h"

#endif