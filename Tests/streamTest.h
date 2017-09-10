/**
 * This file contains a number of template
 * classes used to confirm the functionality
 * of cryptographic stream objects.
 *
 */

///@cond INTERNAL

#ifndef STREAM_TEST_H
#define STREAM_TEST_H

#include "UnitTest/UnitTest.h"
#include "../streamCipher.h"

namespace test {

    //Stream test frame
    template <class streamType>
    class streamTest:public singleTest
    {
    protected:
        std::string _streamName;
		os::smart_ptr<crypto::streamCipher> _cipher;
		os::smart_ptr<crypto::streamCipher> _cipher2;
    public:
        streamTest(std::string tn, std::string streamName, uint8_t* seed=NULL, int seedLen=0):
            singleTest(tn+": "+streamName)
        {
            _streamName=streamName;
			if(seedLen!=0 && seed!=NULL)
			{
				_cipher=os::smart_ptr<crypto::streamCipher>(new streamType(seed,seedLen),os::shared_type);
				_cipher2=os::smart_ptr<crypto::streamCipher>(new streamType(seed,seedLen),os::shared_type);
			}
			else
			{
				uint8_t arr[16];
				memset(arr,0,16);
				_cipher=os::smart_ptr<crypto::streamCipher>(new streamType(arr,16),os::shared_type);
				_cipher2=os::smart_ptr<crypto::streamCipher>(new streamType(arr,16),os::shared_type);
			}
        }
        virtual ~streamTest(){}
    };

	//Name test
	template <class streamType>
    class streamNameTest:public streamTest<streamType>
    {
	public:
		streamNameTest(std::string streamName):streamTest<streamType>("Name Test",streamName){}
		virtual ~streamNameTest(){}

		void test()
        {
            std::string locString = "streamTest.h, streamNameTest::test()";
			if(streamTest<streamType>::_cipher->algorithmName() == "NULL Algorithm")
				throw os::smart_ptr<std::exception>(new generalTestException("Algorithm marked NULL",locString),os::shared_type);
			if(streamTest<streamType>::_cipher->algorithmName() != streamTest<streamType>::_streamName)
				throw os::smart_ptr<std::exception>(new generalTestException("Name mis-match!",locString),os::shared_type);
		}
	};

	//ID test
	template <class streamType>
    class streamIDTest:public streamTest<streamType>
    {
		int _streamInt;
	public:
		streamIDTest(std::string streamName, int streamInt):streamTest<streamType>("ID Test",streamName){_streamInt=streamInt;}
		virtual ~streamIDTest(){}

		void test()
        {
            std::string locString = "streamTest.h, streamIDTest::test()";
			if(streamTest<streamType>::_cipher->algorithm() == crypto::algo::streamNULL)
				throw os::smart_ptr<std::exception>(new generalTestException("Stream ID matches the NULL case!",locString),os::shared_type);
			if(streamTest<streamType>::_cipher->algorithm() != _streamInt)
				throw os::smart_ptr<std::exception>(new generalTestException("Stream ID does not match the expected case!",locString),os::shared_type);
		}
	};

	//Block test
	template <class streamType>
    class streamBlockTest:public streamTest<streamType>
    {
		int _iteration;
	public:
		streamBlockTest(std::string streamName, int iteration,uint8_t* seed, int seedLen):
			streamTest<streamType>("Stream Block ("+std::to_string((long long unsigned int)iteration)+")",streamName,seed,seedLen){_iteration=iteration;}
		virtual ~streamBlockTest(){}

		void test()
        {
            std::string locString = "streamTest.h, streamBlockTest::test(), iteration "+std::to_string((long long unsigned int)_iteration);

			//Init an encoder and decoder
            crypto::streamEncrypter strEn(streamTest<streamType>::_cipher);
			crypto::streamDecrypter strDe(streamTest<streamType>::_cipher2);

			uint8_t arr1[256];
			uint16_t markVal;
			uint8_t arr2[256];

			//Check 1 forward
			for(int i=0;i<256;++i)
				arr1[i]=rand();
			memcpy(arr2,arr1,256);
			strEn.sendData(arr1,256,markVal);
			strDe.recieveData(arr1,256,markVal);

			//Check for differences
			for(int i=0;i<256;++i)
			{
				if(arr1[i]!=arr2[i]) throw os::smart_ptr<std::exception>(new generalTestException("Initial simple check failed",locString),os::shared_type);
			}

			//Check 1 forward (again)
			for(int i=0;i<256;++i)
				arr1[i]=rand();
			memcpy(arr2,arr1,256);
			strEn.sendData(arr1,256,markVal);
			strDe.recieveData(arr1,256,markVal);

			//Check for differences
			for(int i=0;i<256;++i)
			{
				if(arr1[i]!=arr2[i]) throw os::smart_ptr<std::exception>(new generalTestException("Secondary simple check failed",locString),os::shared_type);
			}

			//Check 2 forward
			strEn.sendData(arr1,256,markVal);
			for(int i=0;i<256;++i)
				arr1[i]=rand();
			memcpy(arr2,arr1,256);
			strEn.sendData(arr1,256,markVal);
			strDe.recieveData(arr1,256,markVal);

			//Check for differences
			for(int i=0;i<256;++i)
			{
				if(arr1[i]!=arr2[i]) throw os::smart_ptr<std::exception>(new generalTestException("2 forward check failed",locString),os::shared_type);
			}

			//Check 4 forward
			strEn.sendData(arr1,256,markVal);
			strEn.sendData(arr1,256,markVal);
			strEn.sendData(arr1,256,markVal);
			for(int i=0;i<256;++i)
				arr1[i]=rand();
			memcpy(arr2,arr1,256);
			strEn.sendData(arr1,256,markVal);
			strDe.recieveData(arr1,256,markVal);

			//Check for differences
			for(int i=0;i<256;++i)
			{
				if(arr1[i]!=arr2[i]) throw os::smart_ptr<std::exception>(new generalTestException("4 forward check failed",locString),os::shared_type);
			}
		}
	};

    //General Stream Test suite
	template <class streamType>
    class streamTestSuite:public testSuite
    {
    public:
        streamTestSuite(std::string streamName, int streamInt):testSuite(streamName+" Stream")
		{
			pushTest(os::smart_ptr<singleTest>(new streamNameTest<streamType>(streamName),os::shared_type));
			pushTest(os::smart_ptr<singleTest>(new streamIDTest<streamType>(streamName,streamInt),os::shared_type));

			//Cycle block test 5 times
			uint8_t arr[16];
			for(int i=1;i<6;++i)
			{
				for(int c=0;c<16;c++) arr[c]=rand();
				pushTest(os::smart_ptr<singleTest>(new streamBlockTest<streamType>(streamName,i,arr,16),os::shared_type));
			}
		}
        virtual ~streamTestSuite(){}
    };

	//RC4 Stream test
	class RC4StreamTestSuite:public streamTestSuite<crypto::RCFour>
	{
	public:
		RC4StreamTestSuite();
		virtual ~RC4StreamTestSuite(){}
	};
}

#endif

///@endcond