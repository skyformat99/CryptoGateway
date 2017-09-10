/**
 * Contains declarations need to bind
 * the CryptoGateway test library to
 * the unit test driver.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_TEST_H
#define CRYPTO_TEST_H

#include "UnitTest/UnitTest.h"
#include "../CryptoGateway.h"

namespace test
{
    //CryptoGateway Library Test
	class CryptoGatewayReducedTest: public libraryTests
	{
	public:
		CryptoGatewayReducedTest();
		virtual ~CryptoGatewayReducedTest(){}
	};
    class CryptoGatewayLibraryTest: public CryptoGatewayReducedTest
    {
    public:
        CryptoGatewayLibraryTest();
        virtual ~CryptoGatewayLibraryTest(){}
    };

    //Crypto Number tests
    class BasicNumberTest: public testSuite
    {
    public:
        BasicNumberTest();
        virtual ~BasicNumberTest(){}
    };
    class IntegerTest: public testSuite
    {
    public:
        IntegerTest();
        virtual ~IntegerTest(){}
    };
}

#endif

///@endcond