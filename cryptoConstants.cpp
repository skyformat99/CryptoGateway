/**
 * Binds all of the scoped constants
 * used by CryptoGateway.  The nested
 * namespaces ensure that there is no
 * ambiguity as to the purpose and
 * nature of the constants.
 **/

 ///@cond INTERNAL

#ifndef CRYPTOCONSTANTS_CPP
#define CRYPTOCONSTANTS_CPP

#include "cryptoConstants.h"
#include <string>

namespace crypto
{
	namespace numberType
	{
		/** @brief Default number type integer ID
		 */
		const int Default=crypto_numbertype_default;
		/** @brief Base-10 number type integer ID
		 */
		const int Base10=crypto_numbertype_base10;
	}
	namespace numberName
	{
		/** @brief Default number type string ID
		 */
		const std::string Default=std::string(crypto_numbername_default);
		/** @brief Base-10 number type string ID
		 */
		const std::string Base10=std::string(crypto_numbername_base10);
	}
    namespace algo
    {
		/** @brief Number of test cycle for prime test
		 */
        const uint16_t primeTestCycle=20;

		/** @brief NULL hash algorithm ID
		 */
        const uint16_t hashNULL=0;
		/** @brief XOR hash algorithm ID
		 */
        const uint16_t hashXOR=1;
		/** @brief RC-4 hash algorithm ID
		 */
        const uint16_t hashRC4=2;

		/** @brief NULL stream algorithm ID
		 */
		const uint16_t streamNULL=0;
		/** @brief RC-4 stream algorithm ID
		 */
		const uint16_t streamRC4=1;

		/** @brief NULL public-key algorithm ID
		 */
		const uint16_t publicNULL=0;
		/** @brief RSA public-key algorithm ID
		 */
		const uint16_t publicRSA=1;
    }
	namespace file
	{
		/**@brief Lock with public key, unlock with private
		 */
		const uint16_t PRIVATE_UNLOCK=0;
		/**@brief Lock with private key, unlock with public
		 */
		const uint16_t PUBLIC_UNLOCK=1;
		/**@brief Lock with both public and private
		 */
		const uint16_t DOUBLE_LOCK=2;
	}
    namespace size
    {
		/** @brief 64 bit hash size in bytes
		 */
        const uint16_t hash64=8;
		/** @brief 128 bit hash size in bytes
		 */
        const uint16_t hash128=16;
		/** @brief 256 bit hash size in bytes
		 */
        const uint16_t hash256=32;
        /** @brief 512 bit hash size in bytes
		 */
		const uint16_t hash512=64;
        /** @brief Default hash size in bytes
		 */
		const uint16_t defaultHash=hash256;

		/** @brief Steam cipher maximum seed size
		 */
		const uint16_t STREAM_SEED_MAX=2506;
		/** @brief Maximum seed size for RC-4
		 */
		const uint16_t RC4_MAX=2506;

		/** @brief 128 bit public-key size in uint32_t
		 */
		const uint16_t public128=4;
		/** @brief 256 bit public-key size in uint32_t
		 */
		const uint16_t public256=8;
		/** @brief 512 bit public-key size in uint32_t
		 */
		const uint16_t public512=16;
		/** @brief 1024 bit public-key size in uint32_t
		 */
		const uint16_t public1024=32;
		/** @brief 2048 bit public-key size in uint32_t
		 */
		const uint16_t public2048=64;

		/** @brief Maximum characters in a group name
		 */
		const uint16_t GROUP_SIZE=20;
		/** @brief Maximum characters in a node name
		 */
		const uint16_t NAME_SIZE=20;

		namespace stream
		{
			/** @brief Packet size for streaming gateway
			*/
			const uint16_t PACKETSIZE=508;
			/** @brief Packet holding size
			 *
			 * This variable defines how
			 * many packets stream encoders
			 * and decoders hold.
			 */
			const uint16_t DECRYSIZE=100;
			/** @brief Packet history size
			 *
			 * This variable defines how
			 * many historical packets stream
			 * decoders must hold in their
			 * history.
			 */
			const uint16_t BACKCHECK=10;
			/** @brief Stream search starting point
			 *
			 * This variable defines how
			 * far back a stream decoder
			 * automatically searches.
			 */
			const uint16_t LAGCATCH=DECRYSIZE/4;
		}
    }
}

#endif
///@endcond