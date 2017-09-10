/**
 * Consult cryptoConstants.cpp for details.
 * This file merely defines extern references
 * to the global constants in cryptoConstants.cpp.
 **/

 ///@cond INTERNAL

#ifndef CRYPTOCONSTANTS_H
#define CRYPTOCONSTANTS_H

#include "C_Algorithms/cryptoCConstants.h"

#include <stdint.h>
#include <string>

//Scoped C++ variables
namespace crypto
{
	namespace numberType
	{
		extern const int Default;
		extern const int Base10;
	}
	namespace numberName
	{
		extern const std::string Default;
		extern const std::string Base10;
	}
    namespace algo
    {
        extern const uint16_t primeTestCycle;

        extern const uint16_t hashNULL;
        extern const uint16_t hashXOR;
        extern const uint16_t hashRC4;

		extern const uint16_t streamNULL;
		extern const uint16_t streamRC4;

		extern const uint16_t publicNULL;
		extern const uint16_t publicRSA;
    }
	namespace file
	{
		extern const uint16_t PRIVATE_UNLOCK;
		/**@brief Lock with private key, unlock with public
		 */
		extern const uint16_t PUBLIC_UNLOCK;
		/**@brief Lock with both public and private
		 */
		extern const uint16_t DOUBLE_LOCK;
	}
    namespace size
    {
        extern const uint16_t hash64;
        extern const uint16_t hash128;
        extern const uint16_t hash256;
        extern const uint16_t hash512;
        extern const uint16_t defaultHash;

		extern const uint16_t STREAM_SEED_MAX;
		extern const uint16_t RC4_MAX;

		extern const uint16_t public128;
		extern const uint16_t public256;
		extern const uint16_t public512;
		extern const uint16_t public1024;
		extern const uint16_t public2048;

		extern const uint16_t GROUP_SIZE;
		extern const uint16_t NAME_SIZE;

		namespace stream
		{
			extern const uint16_t PACKETSIZE;
			extern const uint16_t DECRYSIZE;
			extern const uint16_t BACKCHECK;
			extern const uint16_t LAGCATCH;
		}
    }
}

#endif
///@endcond