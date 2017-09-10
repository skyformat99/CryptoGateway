/**
 * Since the public key tests are defined by
 * very simple tests, the template testing classes
 * contained in this file are also defined in this
 * file.  There is no .cpp file paired with this
 * particular header.
 *
 */

///@cond INTERNAL

#ifndef PUBLIC_KEY_TEST_H
#define PUBLIC_KEY_TEST_H

#include "UnitTest/UnitTest.h"
#include "../publicKeyPackage.h"
#include "../cryptoPublicKey.h"
#include "testKeyGeneration.h"

namespace test
{
    //Basic saving and loading for public keys
    template <class pkType>
    class generationTest: public singleTest
    {
    public:
        generationTest():singleTest("Generation"){}
        virtual ~generationTest(){}
		void test()
        {
			std::string locString = "publicKeyTest.h, generationTest::test()";

			try
			{
				pkType writeKey(crypto::size::public256);
				while(!writeKey.getN()) os::sleep(50);
				if(writeKey.generating())
					throw os::smart_ptr<std::exception>(new generalTestException("Write key says its generating",locString),os::shared_type);
				writeKey.generateNewKeys();
				while(writeKey.generating()) os::sleep(50);

				writeKey.setFileName("keytest.dmp");
				writeKey.save();

				pkType readKey("keytest.dmp");

				if(readKey.size()!=writeKey.size())
					throw os::smart_ptr<std::exception>(new generalTestException("Read sizes do no match",locString),os::shared_type);
				if(readKey.algorithm()!=writeKey.algorithm())
					throw os::smart_ptr<std::exception>(new generalTestException("Algorithms do no match",locString),os::shared_type);

				if(!readKey.getN())
					throw os::smart_ptr<std::exception>(new generalTestException("NULL n value",locString),os::shared_type);
				if(readKey!=writeKey)
					throw os::smart_ptr<std::exception>(new generalTestException("Failed to read key",locString),os::shared_type);

				if(readKey.history()!=writeKey.history())
					throw os::smart_ptr<std::exception>(new generalTestException("History size failed to match!",locString),os::shared_type);

				os::smart_ptr<crypto::number> wnum=writeKey.getOldN();
				os::smart_ptr<crypto::number> rnum=readKey.getOldN();

				if(!wnum)
					throw os::smart_ptr<std::exception>(new generalTestException("No old n in write key",locString),os::shared_type);
				if(!rnum)
					throw os::smart_ptr<std::exception>(new generalTestException("No old n in read key",locString),os::shared_type);
				if((*wnum) != (*rnum))
					throw os::smart_ptr<std::exception>(new generalTestException("Old \'n\' values do not match",locString),os::shared_type);
				if((*readKey.getN()) == (*rnum))
					throw os::smart_ptr<std::exception>(new generalTestException("Old and new n values match",locString),os::shared_type);
			}
			catch(crypto::errorPointer e)
			{
				if(os::check_exists("keytest.dmp"))
					os::delete_file("keytest.dmp");
				throw os::smart_ptr<std::exception>(new generalTestException(e->errorTitle(),e->errorDescription()),os::shared_type);
			}
			catch(os::smart_ptr<std::exception> e)
			{
				if(os::check_exists("keytest.dmp"))
					os::delete_file("keytest.dmp");
				throw e;
			}
			catch(...)
			{
				if(os::check_exists("keytest.dmp"))
					os::delete_file("keytest.dmp");
				throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
			}
			if(os::check_exists("keytest.dmp")) os::delete_file("keytest.dmp");
		}
    };

    //Simple key test
    template <class pkType,class numberType>
    class basicPublicKeyTest:public singleTest
    {
        uint16_t publicLen;
    public:
        basicPublicKeyTest(uint16_t pl):singleTest("Basic Test: "+std::to_string((long long unsigned int)pl*32)){publicLen=pl;}
        virtual ~basicPublicKeyTest(){}

        void test()
        {
			std::string locString = "publicKeyTest.h, basicPublicKeyTest::test()";

            try
            {
                os::smart_ptr<pkType> pk1=getStaticKeys<pkType>(publicLen,0);
                os::smart_ptr<pkType> pk2=getStaticKeys<pkType>(publicLen,1);

                numberType n1(publicLen);
                for(uint16_t i=0;i<publicLen-1;++i)
                    n1[i]=rand();
                numberType en1=n1;
                numberType en2=n1;

                en1=*os::cast<numberType,crypto::number>(pk1->encode(&en1));
                en2=*os::cast<numberType,crypto::number>(pk2->encode(&en2));
                if(en1==en2)
                    throw os::smart_ptr<std::exception>(new generalTestException("Public keys encrypted the same number",locString),os::shared_type);
                en1=*os::cast<numberType,crypto::number>(pk1->decode(&en1));
                en2=*os::cast<numberType,crypto::number>(pk2->decode(&en2));
                if(en1!=n1)
                    throw os::smart_ptr<std::exception>(new generalTestException("Key 1 failed",locString),os::shared_type);
                if(en2!=n1)
                    throw os::smart_ptr<std::exception>(new generalTestException("Key 2 failed",locString),os::shared_type);
            }
            catch(crypto::errorPointer ep){throw os::smart_ptr<std::exception>(new generalTestException(ep->what(),locString),os::shared_type);}
            catch(os::smart_ptr<std::exception> e){throw e;}
            catch(...){throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);}
        }
    };

	//Byte key test
    template <class pkType>
    class byteKeyTest:public singleTest
    {
        uint16_t publicLen;
    public:
        byteKeyTest(uint16_t pl):singleTest("Byte Test: "+std::to_string((long long unsigned int)pl*32)){publicLen=pl;}
        virtual ~byteKeyTest(){}

        void test()
        {
			std::string locString = "publicKeyTest.h, byteKeyTest::test()";

            try
            {
                os::smart_ptr<pkType> pk1=getStaticKeys<pkType>(publicLen,0);

				unsigned int len=publicLen*sizeof(uint32_t);
				os::smart_ptr<unsigned char> char1(new unsigned char[len],os::shared_type);
				os::smart_ptr<unsigned char> char2(new unsigned char[len],os::shared_type);
				memset(char1.get(),0,len);
                for(unsigned i=0;i<len-1;++i)
                    char1[i]=rand();
                memcpy(char2.get(),char1.get(),len);

                pk1->encode(char1.get(),len);
                pk1->crypto::publicKey::decode(char1.get(),len);
                for(unsigned i=0;i<len;++i)
				{
					if(char1[i]!=char2[i])
						throw os::smart_ptr<std::exception>(new generalTestException("Encryption failed",locString),os::shared_type);
				}
            }
            catch(crypto::errorPointer ep){throw os::smart_ptr<std::exception>(new generalTestException(ep->what(),locString),os::shared_type);}
            catch(os::smart_ptr<std::exception> e){throw e;}
            catch(...){throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);}
        }
    };

	//Public key search test
    template <class pkType,class numberType>
    class publicKeySearchTest:public singleTest
    {
        uint16_t publicLen;
    public:
        publicKeySearchTest(uint16_t pl):singleTest("Search Test: "+std::to_string((long long unsigned int)pl*32)){publicLen=pl;}
        virtual ~publicKeySearchTest(){}

        void test()
        {
			std::string locString = "publicKeyTest.h, publicKeySearchTest::test()";

            try
            {
				uint32_t *arr_n1,*arr_d1;
				uint32_t *arr_n2,*arr_d2;
				findKeys<pkType>(arr_n1,arr_d1,publicLen,0);
				findKeys<pkType>(arr_n2,arr_d2,publicLen,1);

				os::smart_ptr<crypto::number> n1(new numberType(arr_n1,publicLen),os::shared_type);
				os::smart_ptr<crypto::number> n2(new numberType(arr_n2,publicLen),os::shared_type);
				os::smart_ptr<crypto::number> d1(new numberType(arr_d1,publicLen),os::shared_type);
				os::smart_ptr<crypto::number> d2(new numberType(arr_d2,publicLen),os::shared_type);

				//Create public key
				pkType pk(os::cast<numberType,crypto::number>(n1),os::cast<numberType,crypto::number>(d1),publicLen);
				pk.addKeyPair(n2,d2);

				//Search by number
				size_t histVal;
				bool typ;
				if(!pk.searchKey(n1,histVal,typ))
					throw os::smart_ptr<std::exception>(new generalTestException("Could not find key N1",locString),os::shared_type);
				if(typ!=crypto::publicKey::PUBLIC || histVal!=0)
					throw os::smart_ptr<std::exception>(new generalTestException("N1 search returned incorrectly",locString),os::shared_type);
				if(!pk.searchKey(d2,histVal,typ))
					throw os::smart_ptr<std::exception>(new generalTestException("Could not find key D2",locString),os::shared_type);
				if(typ!=crypto::publicKey::PRIVATE || histVal!=crypto::publicKey::CURRENT_INDEX)
					throw os::smart_ptr<std::exception>(new generalTestException("D2 search returned incorrectly",locString),os::shared_type);

				//Search by hash
				size_t charLen;
				os::smart_ptr<unsigned char> ptrArr=n2->getCompCharData(charLen);
				if(!pk.searchKey(crypto::rc4Hash::hash256Bit(ptrArr.get(),charLen),histVal,typ))
					throw os::smart_ptr<std::exception>(new generalTestException("Could not find key N2",locString),os::shared_type);
				if(typ!=crypto::publicKey::PUBLIC || histVal!=crypto::publicKey::CURRENT_INDEX)
					throw os::smart_ptr<std::exception>(new generalTestException("N2 search returned incorrectly",locString),os::shared_type);
				ptrArr=d1->getCompCharData(charLen);
				if(!pk.searchKey(crypto::rc4Hash::hash256Bit(ptrArr.get(),charLen),histVal,typ))
					throw os::smart_ptr<std::exception>(new generalTestException("Could not find key D1",locString),os::shared_type);
				if(typ!=crypto::publicKey::PRIVATE || histVal!=0)
					throw os::smart_ptr<std::exception>(new generalTestException("D1 search returned incorrectly",locString),os::shared_type);

            }
            catch(crypto::errorPointer ep){throw os::smart_ptr<std::exception>(new generalTestException(ep->what(),locString),os::shared_type);}
            catch(os::smart_ptr<std::exception> e){throw e;}
            catch(...){throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);}
        }
    };

    //Simple key test
    template <class pkType>
    class packageSearchTest:public singleTest
    {
    public:
        packageSearchTest():singleTest("Package Search"){}
        virtual ~packageSearchTest(){}

        void test()
        {
			std::string locString = "publicKeyTest.h, packageSearchTest::test()";
			if(pkType::staticAlgorithm()==crypto::algo::publicNULL)
				throw os::smart_ptr<std::exception>(new generalTestException("Algorithm registered as NULL",locString),os::shared_type);

			os::smart_ptr<crypto::publicKeyPackageFrame> pck=crypto::publicKeyTypeBank::singleton()->findPublicKey(pkType::staticAlgorithm());
			if(!pck)
				throw os::smart_ptr<std::exception>(new generalTestException("Cannot find algorithm by ID!",locString),os::shared_type);
			if(pck->algorithmName()!=pkType::staticAlgorithmName())
				throw os::smart_ptr<std::exception>(new generalTestException("Algorithm name mis-match!",locString),os::shared_type);

			pck=crypto::publicKeyTypeBank::singleton()->findPublicKey(pkType::staticAlgorithmName());
			if(!pck)
				throw os::smart_ptr<std::exception>(new generalTestException("Cannot find algorithm by name!",locString),os::shared_type);
			if(pck->algorithm()!=pkType::staticAlgorithm())
				throw os::smart_ptr<std::exception>(new generalTestException("Algorithm ID mis-match!",locString),os::shared_type);
		}
	};

    //General public key Test suite
    template <class pkType, class numberType>
    class publicKeySuite:public testSuite
    {
    public:
        publicKeySuite(std::string pkName):testSuite(pkName+": Public Key")
        {
            pushTest(os::smart_ptr<singleTest>(new generationTest<pkType>(),os::shared_type));

			pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType,numberType>(crypto::size::public128),os::shared_type));
			pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType,numberType>(crypto::size::public256),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType,numberType>(crypto::size::public512),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType,numberType>(crypto::size::public1024),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new basicPublicKeyTest<pkType,numberType>(crypto::size::public2048),os::shared_type));

			pushTest(os::smart_ptr<singleTest>(new byteKeyTest<pkType>(crypto::size::public128),os::shared_type));
			pushTest(os::smart_ptr<singleTest>(new byteKeyTest<pkType>(crypto::size::public256),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new byteKeyTest<pkType>(crypto::size::public512),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new byteKeyTest<pkType>(crypto::size::public1024),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new byteKeyTest<pkType>(crypto::size::public2048),os::shared_type));

			pushTest(os::smart_ptr<singleTest>(new publicKeySearchTest<pkType,numberType>(crypto::size::public128),os::shared_type));
			pushTest(os::smart_ptr<singleTest>(new publicKeySearchTest<pkType,numberType>(crypto::size::public256),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new publicKeySearchTest<pkType,numberType>(crypto::size::public512),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new publicKeySearchTest<pkType,numberType>(crypto::size::public1024),os::shared_type));
            pushTest(os::smart_ptr<singleTest>(new publicKeySearchTest<pkType,numberType>(crypto::size::public2048),os::shared_type));

			pushTest(os::smart_ptr<singleTest>(new packageSearchTest<pkType>(),os::shared_type));
        }
        virtual ~publicKeySuite(){}
    };
    //Public key test suite
    class RSASuite:public publicKeySuite<crypto::publicRSA,crypto::integer>
    {
    public:
        RSASuite():publicKeySuite<crypto::publicRSA,crypto::integer>("RSA")
        {}
        virtual ~RSASuite(){}
    };
}

#endif

///@endcond