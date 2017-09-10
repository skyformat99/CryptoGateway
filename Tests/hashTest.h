/**
 * This file contains a number of template
 * classes used to confirm the functionality
 * of cryptographic hash algorithms.
 *
 */

///@cond INTERNAL

#ifndef HASH_TEST_H
#define HASH_TEST_H

#include "UnitTest/UnitTest.h"
#include "../cryptoHash.h"
#include "../RC4_Hash.h"

namespace test {

    //Hash test frame
    template <class hashClass>
    class hashTest:public singleTest
    {
    protected:
        std::string _hashName;
        uint16_t _hashSize;
    public:
        hashTest(std::string tn,std::string hashName, uint16_t hashSize):
            singleTest(tn+": "+hashName+" "+std::to_string((long long unsigned int)hashSize*8)+" bit")
        {
            _hashName=hashName;
            _hashSize=hashSize;
        }
        virtual ~hashTest(){}
    };

    //Sets a random hash value (for testing misc hash functionality)
    template <class hashClass>
    hashClass randomHash(uint16_t hashType)
    {
        unsigned char data[1024];

        for(int i=0;i<1024;++i)
            data[i]=(unsigned char)rand();

        return crypto::hashData<hashClass>(hashType,data,512);
    }

    //Constructor test
    template <class hashClass>
    class hashConstructorTest:public hashTest<hashClass>
    {
    public:
        hashConstructorTest(std::string tn,std::string hashName, uint16_t hashSize):
            hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashConstructorTest(){}

        virtual void test()
        {
            std::string locString = "hashTest.h, hashConstructorTest::test()";

            //Attempts the random hash 20 times
            for(int i=0;i<20;++i)
            {
                hashClass hsh1=randomHash<hashClass>(hashTest<hashClass>::_hashSize);
                hashClass hsh2(hsh1);
                hashClass hsh3=hsh1;

                //Copy constructor
                if(hsh1!=hsh2)
                    throw os::smart_ptr<std::exception>(new generalTestException("Copy constructor failed",locString),os::shared_type);
                if(hsh1!=hsh3)
                    throw os::smart_ptr<std::exception>(new generalTestException("Equals constructor failed",locString),os::shared_type);
            }
        }
    };

    //Compare test
    template <class hashClass>
    class hashCompareTest:public hashTest<hashClass>
    {
    public:
        hashCompareTest(std::string tn,std::string hashName, uint16_t hashSize):
            hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashCompareTest(){}

        virtual void test()
        {
            std::string locString = "hashTest.h, hashCompareTest::test()";

            hashClass t1=crypto::hashData<hashClass>(hashTest<hashClass>::_hashSize,NULL,0);
            hashClass t2=crypto::hashData<hashClass>(hashTest<hashClass>::_hashSize,NULL,0);

            if(t1.compare(&t2)!=0)
                throw os::smart_ptr<std::exception>(new generalTestException("t1 should equal t2",locString),os::shared_type);
            if(t2.compare(&t1)!=0)
                throw os::smart_ptr<std::exception>(new generalTestException("t2 should equal t1",locString),os::shared_type);

            t1[0]=10;
            if(t1.compare(&t2)!=1)
                throw os::smart_ptr<std::exception>(new generalTestException("t1 should be greater than t2",locString),os::shared_type);
            if(t2.compare(&t1)!=-1)
                throw os::smart_ptr<std::exception>(new generalTestException("t2 should be less than t1",locString),os::shared_type);

            t2[0]=12;
            if(t1.compare(&t2)!=-1)
                throw os::smart_ptr<std::exception>(new generalTestException("t1 should be less than t2",locString),os::shared_type);
            if(t2.compare(&t1)!=1)
                throw os::smart_ptr<std::exception>(new generalTestException("t2 should be greater than t1",locString),os::shared_type);
        }
    };

    //Equality operator test
    template <class hashClass>
    class hashEqualityOperatorTest:public hashTest<hashClass>
    {
    public:
        hashEqualityOperatorTest(std::string tn,std::string hashName, uint16_t hashSize):
        hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashEqualityOperatorTest(){}

        virtual void test()
        {
            std::string locString = "hashTest.h, hashEqualityOperatorTest::test()";

            //Attempts the random hash 20 times
            for(int i=0;i<20;++i)
            {
                hashClass hsh1=randomHash<hashClass>(hashTest<hashClass>::_hashSize);
                hashClass hsh2=randomHash<hashClass>(hashTest<hashClass>::_hashSize);

                int compVal = hsh1.compare(&hsh2);

                if(compVal==0)
                {
                    if(hsh1!=hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Not equals failed",locString),os::shared_type);
                    if(hsh1<hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Less than failed",locString),os::shared_type);
                    if(hsh1>hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Greater than failed",locString),os::shared_type);
                }
                else if(compVal==1)
                {
                    if(hsh1==hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Equals failed",locString),os::shared_type);
                    if(hsh1<hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Less than failed",locString),os::shared_type);
                    if(hsh1<=hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Less than/equal to failed",locString),os::shared_type);
                }
                else
                {
                    if(hsh1==hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Equals failed",locString),os::shared_type);
                    if(hsh1>hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Greater than failed",locString),os::shared_type);
                    if(hsh1>=hsh2)
                        throw os::smart_ptr<std::exception>(new generalTestException("Greater than/equal to failed",locString),os::shared_type);
                }
            }
        }
    };

    //String test
    template <class hashClass>
    class hashStringTest:public hashTest<hashClass>
    {
    public:
        hashStringTest(std::string tn,std::string hashName, uint16_t hashSize):
        hashTest<hashClass>(tn,hashName,hashSize){}
        virtual ~hashStringTest(){}

        virtual void test()
        {
            std::string locString = "hashTest.h, hashStringTest::test()";

            hashClass hsh1=crypto::hashData<hashClass>(hashTest<hashClass>::_hashSize,NULL,0);

            std::string targ;
            for(uint16_t i=0;i<hsh1.size()*2;++i)
            {
                targ+='0';
            }
            if(targ!=hsh1.toString())
                throw os::smart_ptr<std::exception>(new generalTestException("To string (0) failed",locString),os::shared_type);
            targ[targ.length()-1]='8';
            hsh1[0]=8;
            if(targ!=hsh1.toString())
                throw os::smart_ptr<std::exception>(new generalTestException("To string (1) failed",locString),os::shared_type);

            //Convert to string and back
            for(int i=0;i<20;++i)
            {
                hashClass hsh1=randomHash<hashClass>(hashTest<hashClass>::_hashSize);
                hashClass hsh2;
                std::string str=hsh1.toString();

                hsh2.fromString(str);
                if(hsh1!=hsh2)
                    throw os::smart_ptr<std::exception>(new generalTestException("From string failed",locString),os::shared_type);
            }
        }
    };

    //Hash test suite
    template <class hashClass>
    class hashSuite:public testSuite
    {
    public:
        hashSuite(std::string hashName):
            testSuite(hashName)
        {
            uint16_t hSize;
            for(int i=0;i<4;++i)
            {
                if(i==0) hSize=crypto::size::hash64;
                else if(i==1) hSize=crypto::size::hash128;
                else if(i==2) hSize=crypto::size::hash256;
                else if(i==3) hSize=crypto::size::hash512;

				pushTest(os::smart_ptr<singleTest>(new hashConstructorTest<hashClass>("Constructor",hashName,hSize),os::shared_type));
                pushTest(os::smart_ptr<singleTest>(new hashCompareTest<hashClass>("Compare",hashName,hSize),os::shared_type));
                pushTest(os::smart_ptr<singleTest>(new hashEqualityOperatorTest<hashClass>("Equality Operators",hashName,hSize),os::shared_type));
                pushTest(os::smart_ptr<singleTest>(new hashStringTest<hashClass>("String Conversion",hashName,hSize),os::shared_type));
            }
        }
        virtual ~hashSuite(){}
    };

    //XOR Hash test
    class xorTestSuite:public hashSuite<crypto::xorHash>
    {
    public:
        xorTestSuite();
        virtual ~xorTestSuite(){}
    };

	//RC-4 Hash test
    class RC4HashTestSuite:public hashSuite<crypto::rc4Hash>
    {
    public:
        RC4HashTestSuite();
        virtual ~RC4HashTestSuite(){}
    };
}

#endif

///@endcond