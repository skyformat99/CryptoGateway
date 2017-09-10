/**
 * This file contains algorithm-specific
 * cryptographic hash testing.  These tests
 * confirm that the respective hash algorithms
 * are outputting their expected value.
 *
 */

///@cond INTERNAL

#ifndef HASH_TEST_CPP
#define HASH_TEST_CPP

#include "hashTest.h"

using namespace test;

/*================================================================
	xor Hash
 ================================================================*/

    //Basic xor test
    void basicXORTest()
    {
        std::string locString = "hashTest.cpp, basicXORTest()";

        unsigned char val[128];
        memset(val,0,128);
        val[0]=6;
        val[64]=3;

        crypto::xorHash h1=crypto::xorHash::hash64Bit(val,128);
        crypto::xorHash h2=crypto::xorHash::hash64Bit(NULL,0);
        h2[0]=5;

        if(h1!=h2)
            generalTestException::throwException("XOR hash algorithm failed",locString);
    }
    //xor Test suite
    xorTestSuite::xorTestSuite():
        hashSuite<crypto::xorHash>("XOR")
    {
        pushTest("XOR Algorithm",&basicXORTest);
    }

/*================================================================
	RC4 Hash
 ================================================================*/

    //Basic xor test
    void basicRC4Test()
    {
        std::string locString = "hashTest.cpp, basicRC4Test()";

        unsigned char val[128];
        memset(val,0,128);
        val[0]=6;
        val[64]=3;

		crypto::rc4Hash h1=crypto::rc4Hash::hash64Bit(val,128);
        crypto::rc4Hash h2;
		h2.fromString("FAFF300339376F54");

        if(h1!=h2)
            generalTestException::throwException("XOR hash algorithm failed",locString);
    }
    //xor Test suite
    RC4HashTestSuite::RC4HashTestSuite():
        hashSuite<crypto::rc4Hash>("RC-4 Hash")
    {
        pushTest("RC-4 Algorithm",&basicRC4Test);
    }

#endif

///@endcond