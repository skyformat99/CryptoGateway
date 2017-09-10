/**
 * Binds all test suites for the
 * test::CryptoGatewayLibraryTest.
 * This library test is called
 * "CryptoGateway."
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_TEST_CPP
#define CRYPTO_TEST_CPP

#include "cryptoTest.h"
#include "c_cryptoTesting.h"
#include "hashTest.h"
#include "streamTest.h"
#include "cryptoFileTest.h"
#include "publicKeyTest.h"
#include "testKeyGeneration.h"
#include "gatewayTest.h"

using namespace test;

/*================================================================
	CryptoGatewayLibraryTest
 ================================================================*/

    //Constructor
    CryptoGatewayReducedTest::CryptoGatewayReducedTest():
        libraryTests("CryptoGateway")
    {
        pushSuite(os::smart_ptr<testSuite>(new C_BaseTenSuite(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new BasicNumberTest(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new IntegerTest(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new xorTestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new RC4HashTestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new RC4StreamTestSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new keyBankSuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new gatewaySuite(),os::shared_type));
    }
	//Full test suite
	CryptoGatewayLibraryTest::CryptoGatewayLibraryTest():
		CryptoGatewayReducedTest()
	{
		pushSuite(os::smart_ptr<testSuite>(new RSASuite(),os::shared_type));
		pushSuite(os::smart_ptr<testSuite>(new cryptoFileTestSuite(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new cryptoEXMLTestSuite(),os::shared_type));
        pushSuite(os::smart_ptr<testSuite>(new userSuite(),os::shared_type));
	}

#endif

///@endcond