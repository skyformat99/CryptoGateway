/**
 * This header contains declarations of the
 * key bank tests and the end-to-end gateway
 * tests.  These tests are not exhaustive,
 * they test basic functionality of both
 * structures.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_TEST_H
#define GATEWAY_TEST_H

#include "UnitTest/UnitTest.h"
#include "../CryptoGateway.h"

namespace test
{
    //Key-bank test suite
    class keyBankSuite: public testSuite
    {
    public:
        keyBankSuite();
        virtual ~keyBankSuite(){}
    };
	//User test suite
    class userSuite: public testSuite
    {
    public:
        userSuite();
        virtual ~userSuite(){}
    };
	//Gateway test suite
    class gatewaySuite: public testSuite
    {
    public:
        gatewaySuite();
        virtual ~gatewaySuite(){}
    };
}

#endif

///@endcond