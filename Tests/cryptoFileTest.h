/**
 * This contains a number of test suites and
 * supporting classes which are designed to
 * test the functionality of saving and loading
 * cryptographic files, both binary and EXML.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_FILE_TEST_H
#define CRYPTO_FILE_TEST_H

#include "UnitTest/UnitTest.h"
#include "../streamPackage.h"
#include "../binaryEncryption.h"
#include "../XMLEncryption.h"

namespace test {

	//Tests binary file saving
	class binaryFileSaveTest:public singleTest
	{
		os::smart_ptr<crypto::streamPackageFrame> streamPackage;
	public:
		binaryFileSaveTest(os::smart_ptr<crypto::streamPackageFrame> spf);
		virtual ~binaryFileSaveTest(){}

		void test();
	};
	//Public key binary file saving
	class publicKeyFileSaveTest:public singleTest
	{
		os::smart_ptr<crypto::publicKey> pubkey;
	public:
		publicKeyFileSaveTest(os::smart_ptr<crypto::publicKey> pk);
		virtual ~publicKeyFileSaveTest(){}

		void test();
	};

	//Crypto File Test
	class cryptoFileTestSuite:public testSuite
	{
	public:
		cryptoFileTestSuite();
		virtual ~cryptoFileTestSuite(){}

		void pushTestPackage(os::smart_ptr<crypto::streamPackageFrame> spf);
		void pushTestPackage(os::smart_ptr<crypto::publicKeyPackageFrame> pkg);
	};

    //Tests EXML file saving
    class exmlFileSaveTest:public singleTest
    {
        os::smart_ptr<crypto::streamPackageFrame> streamPackage;
    public:
        exmlFileSaveTest(os::smart_ptr<crypto::streamPackageFrame> spf);
        virtual ~exmlFileSaveTest(){}

        void test();
    };
    //Tests EXML file saving, public key
    class exmlPublicKeySaveTest:public singleTest
    {
        os::smart_ptr<crypto::publicKey> pubkey;
    public:
        exmlPublicKeySaveTest(os::smart_ptr<crypto::publicKey> pbk);
        virtual ~exmlPublicKeySaveTest(){}

        void test();
    };

    //EXML File Test
    class cryptoEXMLTestSuite:public testSuite
    {
    public:
        cryptoEXMLTestSuite();
        virtual ~cryptoEXMLTestSuite(){}

        void pushTestPackage(os::smart_ptr<crypto::streamPackageFrame> spf);
        void pushTestPackage(os::smart_ptr<crypto::publicKeyPackageFrame> pkg);
    };
}

#endif

///@endcond