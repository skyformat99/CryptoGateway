/**
 * Provides access to the keys generated
 * and stored in staticTestKeys.h and
 * staticTestKeys.cpp.  These keys are
 * always copied into a raw array of
 * uint32_t.
 *
 */

///@cond INTERNAL

#ifndef TEST_KEY_GENERATION_H
#define TEST_KEY_GENERATION_H

#include "UnitTest/UnitTest.h"
#include "staticTestKeys.h"
#include "CryptoGateway/CryptoGateway.h"
#include "Datastructures/Datastructures.h"

namespace test
{
	//Return the positions of the target public key
	void findKeysRaw(uint32_t*& nPtr,uint32_t*& dPtr,uint16_t algoID,uint16_t keySize=crypto::size::public512,unsigned int version=0);
	template <class pkType>
	void findKeys(uint32_t*& nPtr,uint32_t*& dPtr, uint16_t keySize=crypto::size::public512, unsigned int version=0)
	{
		findKeysRaw(nPtr,dPtr,pkType::staticAlgorithm(),keySize,version);
	}

	//Return a public key of the target type with generated keys
	template <class pkType>
	os::smart_ptr<pkType> getStaticKeys(uint16_t keySize=crypto::size::public512, unsigned int version=0)
	{
		uint32_t *n,*d;
		findKeys<pkType>(n,d,keySize,version);

		return os::smart_ptr<pkType>(new pkType(n,d,keySize),os::shared_type);
	}

}

#endif

///@endcond