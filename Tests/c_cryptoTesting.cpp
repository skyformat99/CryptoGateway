/**
 * This file implements test suites which
 * are testing raw C code.  This file
 * currently tests the Base-Ten suite.
 *
 */

///@cond INTERNAL

#ifndef C_CRYPTO_TESTING_CPP
#define C_CRYPTO_TESTING_CPP

#include "../cryptoConstants.h"
#include "c_cryptoTesting.h"
#include <string>

using namespace test;
using namespace os;
using namespace crypto;

    //Confirms NULL value
    void nullNumberType()
    {
        std::string locString = "c_cryptoTesting.cpp, nullNumberType()";
        struct numberType* _nullType = buildNullNumberType();
        if(_nullType == NULL) generalTestException::throwException("NULL type could not be built!",locString);

        if(_nullType->typeID != crypto::numberType::Default) generalTestException::throwException("NULL type ID wrong!",locString);
		if(std::string(_nullType->name) != numberName::Default) generalTestException::throwException("NULL type name wrong!",locString);

        if(_nullType->compare != NULL) generalTestException::throwException("NULL type compare defined!!",locString);

        if(_nullType->addition != NULL) generalTestException::throwException("NULL type addition defined!!",locString);
        if(_nullType->subtraction != NULL) generalTestException::throwException("NULL type subtraction defined!!",locString);

        if(_nullType->rightShift != NULL) generalTestException::throwException("NULL type right shift defined!!",locString);
        if(_nullType->leftShift != NULL) generalTestException::throwException("NULL type left shift defined!!",locString);

        if(_nullType->multiplication != NULL) generalTestException::throwException("NULL type multiplication defined!!",locString);
        if(_nullType->division != NULL) generalTestException::throwException("NULL type division defined!!",locString);
		if(_nullType->modulo != NULL) generalTestException::throwException("NULL type modulo defined!!",locString);

		if(_nullType->exponentiation != NULL) generalTestException::throwException("NULL type exponentiation defined!!",locString);
		if(_nullType->moduloExponentiation != NULL) generalTestException::throwException("NULL type moduloExponentiation defined!!",locString);

		if(_nullType->gcd != NULL) generalTestException::throwException("NULL type gcd defined!!",locString);
		if(_nullType->modInverse != NULL) generalTestException::throwException("NULL type modInverse defined!!",locString);
    }
    //Checks if the base-10 type is constructed properly
    struct numberType* typeCheckBase10(bool errorType=false)throw(os::smart_ptr<std::exception>)
    {
        std::string locString = "c_cryptoTesting.cpp, typeCheckBase10(...)";
        struct numberType* _baseType = buildBaseTenType();
        os::smart_ptr<std::exception> defThrow = os::smart_ptr<std::exception>(new generalTestException("Base-10 type error!",locString),os::shared_type);

        if(_baseType == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type could not be built!",locString);
            else throw defThrow;
        }

        if(_baseType->typeID != crypto::numberType::Base10)
        {
            if(errorType) generalTestException::throwException("Base-10 type ID wrong!",locString);
            else throw defThrow;
        }
		if(std::string(_baseType->name) != numberName::Base10)
        {
            if(errorType) generalTestException::throwException("Base-10 type name wrong!",locString);
            else throw defThrow;
        }

        if(_baseType->compare == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type compare undefined!",locString);
            else throw defThrow;
        }

        if(_baseType->addition == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type addition undefined!",locString);
            else throw defThrow;
        }
        if(_baseType->subtraction == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type addition undefined!",locString);
            else throw defThrow;
        }

        if(_baseType->rightShift == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type right shift undefined!",locString);
            else throw defThrow;
        }
        if(_baseType->leftShift == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type left shift undefined!",locString);
            else throw defThrow;
        }

        if(_baseType->multiplication == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type multiplication undefined!!",locString);
            else throw defThrow;
        }
        if(_baseType->division == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type division undefined!!",locString);
            else throw defThrow;
        }
		if(_baseType->modulo == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type modulo undefined!!",locString);
            else throw defThrow;
        }

		if(_baseType->exponentiation == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type exponentiation undefined!!",locString);
            else throw defThrow;
        }
		if(_baseType->moduloExponentiation == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type moduloExponentiation undefined!!",locString);
            else throw defThrow;
        }

		if(_baseType->gcd == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type gcd undefined!!",locString);
            else throw defThrow;
        }
		if(_baseType->modInverse == NULL)
        {
            if(errorType) generalTestException::throwException("Base-10 type modInverse undefined!!",locString);
            else throw defThrow;
        }

        return _baseType;
    }
    void typeCheckBase10Test()
    {
        typeCheckBase10(true);
    }
    //Compare test
    void base10compareTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10compareTest()";

        uint32_t src1[4];
        uint32_t src2[4];

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

        //0==0
        if(_baseType->compare(src1,src2,4)!=0)
            generalTestException::throwException("0==0 failed!",locString);
        //0<1
        src2[0]=1;
        if(_baseType->compare(src1,src2,4)!=-1)
            generalTestException::throwException("0<1 failed!",locString);
        //2>1
        src1[0]=2;
        if(_baseType->compare(src1,src2,4)!=1)
            generalTestException::throwException("2>1 failed!",locString);
        //2==2
        src2[0]=2;
        if(_baseType->compare(src1,src2,4)!=0)
            generalTestException::throwException("2==2 failed!",locString);

        //0:0:0:2<1:0:0:2
        src2[3]=1;
        if(_baseType->compare(src1,src2,4)!=-1)
            generalTestException::throwException("0:0:0:2<1:0:0:2 failed!",locString);
        //2:0:0:2<1:0:0:2
        src1[3]=2;
        if(_baseType->compare(src1,src2,4)!=1)
            generalTestException::throwException("2:0:0:2<1:0:0:2 failed!",locString);
        //2:0:0:2==2:0:0:2
        src2[3]=2;
        if(_baseType->compare(src1,src2,4)!=0)
            generalTestException::throwException("2:0:0:2==2:0:0:2 failed!",locString);

        //2:0:0:2<2:0:0:3
        src2[0]=3;
        if(_baseType->compare(src1,src2,4)!=-1)
            generalTestException::throwException("2:0:0:2<2:0:0:3 failed!",locString);
        //2:0:0:4<2:0:0:3
        src1[0]=4;
        if(_baseType->compare(src1,src2,4)!=1)
            generalTestException::throwException("2:0:0:4<2:0:0:3 failed!",locString);
        //2:0:0:4==2:0:0:4
        src2[0]=4;
        if(_baseType->compare(src1,src2,4)!=0)
            generalTestException::throwException("2:0:0:4==2:0:0:4 failed!",locString);
    }
    //Addition test
    void base10additionTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10additionTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

        //0+0
        ret=_baseType->addition(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0+0 failed!",locString);

        //0+4
        src2[0]=4;
        ret=_baseType->addition(src1,src2,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("0+4 failed!",locString);
        //4+0
        ret=_baseType->addition(src2,src1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("4+0 failed!",locString);

        //4+4
        src1[0]=4;
        ret=_baseType->addition(src1,src2,dest1,4);
        src2[0]=8;
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("4+4 failed!",locString);

        //Carry
        src1[0]= (uint32_t) -1;
        src2[0]=1;
        ret=_baseType->addition(src1,src2,dest1,4);
        ret=ret&_baseType->addition(src2,src1,dest2,4);
        src1[0]=0;
        src1[1]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || _baseType->compare(dest1,dest2,4)!=0 || !ret)
            generalTestException::throwException("Carry failed!",locString);

        //Double Carry
        src1[0]= (uint32_t) -1;
        src1[1]= (uint32_t) -1;
        src2[0]=1;
        ret=_baseType->addition(src1,src2,dest1,4);
        ret=ret&_baseType->addition(src2,src1,dest2,4);
        src1[0]=0;
        src1[1]=0;
        src1[2]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || _baseType->compare(dest1,dest2,4)!=0 || !ret)
            generalTestException::throwException("Double carry failed!",locString);

        //Overflow
        src1[0]= (uint32_t) -1;
        src1[1]= (uint32_t) -1;
        src1[2]= (uint32_t) -1;
        src1[3]= (uint32_t) -1;
        src2[0]=1;
        ret=_baseType->addition(src1,src2,dest1,4);
        ret=ret|_baseType->addition(src2,src1,dest2,4);
        src2[0]=0;
        if(_baseType->compare(src2,dest1,4)!=0 || _baseType->compare(dest1,dest2,4)!=0 || ret)
            generalTestException::throwException("Overflow failed!",locString);
    }
    //Subtraction test
    void base10subtractionTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10subtractionTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        uint32_t dest2[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

        //0-0
        ret = _baseType->subtraction(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0-0 failed!",locString);

        //4-0
        src1[0]=4;
        ret = _baseType->subtraction(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("4-0 failed!",locString);
        //0-4
        src1[0]=0;
        src2[0]=4;
        ret = _baseType->subtraction(src1,src2,dest1,4);
        if(ret)
            generalTestException::throwException("0-4 didn't overflow!",locString);
        ret = _baseType->addition(dest1,src2,dest2,4);
        if(ret || _baseType->compare(src1,dest2,4)!=0)
            generalTestException::throwException("Overflow carries from 0-4 are incorrect!",locString);
    }
    //Left shift test
    void base10leftShiftTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10rightShiftTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

        //1<<1
        src1[0]=1;
        src2[0]=2;
        ret = _baseType->leftShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("1<<1 failed!",locString);

        //1<<32
        src1[0]=1;
        src2[0]=0;
        src2[1]=1;
        ret = _baseType->leftShift(src1,32,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("1<<32 failed!",locString);

        //1<<33
        src1[0]=1;
        src2[1]=2;
        ret = _baseType->leftShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("1<<33 failed!",locString);

        //Split Shift
        src1[0]=1|(1<<31);
        src2[0]=0;
        src2[1]=2;
        src2[2]=1;
        ret = _baseType->leftShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("Split shift failed!",locString);

        //Split Shift 2
        src1[0]=1|(1<<31);
        src2[0]=0;
        src2[1]=0;
        src2[2]=2;
        src2[3]=1;
        ret = _baseType->leftShift(src1,65,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("Split shift 2 failed!",locString);

        //Overflow (a little)
        ret = _baseType->leftShift(src1,97,dest1,4);
        if(ret)
            generalTestException::throwException("Overflow (a little) failed!",locString);

        //Overflow (a lot)
        src1[0]=0;
        src1[1]=1;
        ret = _baseType->leftShift(src1,129,dest1,4);
        if(ret)
            generalTestException::throwException("Overflow (a lot) failed!",locString);

    }
    //Right shift test
    void base10rightShiftTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10leftShiftTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

        //1>>1
        src1[0]=1;
		ret = _baseType->rightShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("1>>1 failed!",locString);

        //2>>1
        src1[0]=2;
        src2[0]=1;
        ret = _baseType->rightShift(src1,1,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("2>>1 failed!",locString);

        //0:0:1:0>>32
        src1[0]=0;
        src1[1]=1;
        ret = _baseType->rightShift(src1,32,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:0>>32 failed!",locString);

        //0:0:1:0>>31
        src1[0]=0;
        src1[1]=1;
        src2[0]=2;
        ret = _baseType->rightShift(src1,31,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:0>>31 failed!",locString);

        //0:3:0:0>>33
        src1[0]=0;
        src1[1]=0;
        src1[2]=3;
        src2[0]=1<<31;
        src2[1]=1;
        ret = _baseType->rightShift(src1,33,dest1,4);
        if(_baseType->compare(src2,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:3:0:0>>33 failed!",locString);
    }
    //Multiplication test
    void base10multiplicationTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10multiplicationTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0*0
		ret=_baseType->multiplication(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0*0 failed!",locString);

		//0*1
		src2[0]=1;
		ret=_baseType->multiplication(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0*1 failed!",locString);

		//2*1
		src2[0]=1;
		src1[0]=2;
		ret=_baseType->multiplication(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2*1 failed!",locString);

		//2*0:0:1:1
		src2[1]=1;
		ret=_baseType->multiplication(src1,src2,dest1,4);
		src1[1]=2;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2*0:0:1:1 failed!",locString);

		//Carry test
		src1[1]=0;
		src2[0]=1<<31;
		ret=_baseType->multiplication(src1,src2,dest1,4);
		src1[0]=0;
		src1[1]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("Carry failed!",locString);

		//Overflow test
		src2[3]=1<<30;
		ret=_baseType->multiplication(src1,src2,dest1,4);
		if(ret)
			generalTestException::throwException("Overflow 1 failed!",locString);
		ret=_baseType->multiplication(src2,src1,dest1,4);
		if(ret)
			generalTestException::throwException("Overflow 2 failed!",locString);
    }
    //Division test
    void base10divisionTest()
    {
        struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10divisionTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0/0
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || ret)
            generalTestException::throwException("0/0 failed!",locString);

		//0/1
		src2[0]=1;
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0/1 failed!",locString);

		//1/1
		src1[0]=1;
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1/1 failed!",locString);

		//2/1
		src1[0]=2;
		ret=_baseType->division(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2/1 failed!",locString);

		//5/2
		src1[0]=5;
		src2[0]=2;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=2;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("5/2 failed!",locString);

		//5/3
		src1[0]=5;
		src2[0]=3;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("5/3 failed!",locString);

		//0:0:2:2/2
		src1[0]=2;
		src1[1]=2;
		src2[0]=2;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=1;
		src1[1]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:2:2/2 failed!",locString);

		//0:0:2:2/0:0:1:1
		src1[0]=2;
		src1[1]=2;
		src2[0]=1;
		src2[1]=1;
		ret=_baseType->division(src1,src2,dest1,4);
		src1[0]=2;
		src1[1]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:2:2/0:0:1:1 failed!",locString);
    }
	//Modulo
	void base10moduloTest()
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10moduloTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0%0
		ret=_baseType->modulo(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || ret)
            generalTestException::throwException("0%0 failed!",locString);

		//0%2
		src1[0]=0;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0%2 failed!",locString);

		//1%2
		src1[0]=1;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1%2 failed!",locString);

		//2%2
		src1[0]=2;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
		src1[0]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2%2 failed!",locString);

		//3%2
		src1[0]=3;
		src2[0]=2;
		ret=_baseType->modulo(src1,src2,dest1,4);
		src1[0]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("3%2 failed!",locString);
        //3%7
        src1[0]=3;
        src2[0]=7;
        ret=_baseType->modulo(src1,src2,dest1,4);
        src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("3%2 failed!",locString);

		//0:0:1:3%0:0:1:0
		src1[1]=1;
		src1[0]=3;
		src2[1]=1;
		src2[0]=0;
		ret=_baseType->modulo(src1,src2,dest1,4);
		src1[1]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:3%0:0:1:0 failed!",locString);

	}
	//Base 10 exponentiation
	void base10exponentiationTest()
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10exponentiationTest()";

        uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0^0
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0^0 failed!",locString);

		//0^1
		src2[0]=1;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0^1 failed!",locString);

		//1^0
		src1[0]=1;
		src2[0]=1;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1^0 failed!",locString);

		//1^2
		src1[0]=1;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1^2 failed!",locString);

		//2^1
		src1[0]=2;
		src2[0]=1;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2^1 failed!",locString);

		//2^2
		src1[0]=2;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=4;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2^2 failed!",locString);

		//2^3
		src1[0]=2;
		src2[0]=3;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=8;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2^2 failed!",locString);

		//3^2
		src1[0]=3;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=9;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("3^2 failed!",locString);

		//3^3
		src1[0]=3;
		src2[0]=3;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[0]=27;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("3^3 failed!",locString);

		//0:0:1:0^2
		src1[0]=0;
		src1[1]=1;
		src2[0]=2;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[1]=0;
		src1[2]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:0^2 failed!",locString);

		//0:0:1:0^3
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src2[0]=3;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
		src1[1]=0;
		src1[3]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:0^3 failed!",locString);

		//0:0:1:0^4
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src1[3]=0;

		src2[0]=4;
		ret=_baseType->exponentiation(src1,src2,dest1,4);
        if(ret)
            generalTestException::throwException("Overflow failed!",locString);
	}
	//Base 10 modular exponentiation
	void base10modularExponentiationTest()
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10modularExponentiationTest()";

        uint32_t src1[4];
        uint32_t src2[4];
		uint32_t modVal[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;
		modVal[3]=0;  modVal[2]=1;  modVal[1]=0;  modVal[0]=1;

		//0^0
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0^0 failed!",locString);

		//0^1
		src2[0]=1;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0^1 failed!",locString);

		//1^0
		src1[0]=1;
		src2[0]=1;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1^0 failed!",locString);

		//1^2
		src1[0]=1;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1^2 failed!",locString);

		//2^1
		src1[0]=2;
		src2[0]=1;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2^1 failed!",locString);

		//2^2
		src1[0]=2;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=4;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2^2 failed!",locString);

		//2^3
		src1[0]=2;
		src2[0]=3;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=8;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2^2 failed!",locString);

		//3^2
		src1[0]=3;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=9;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("3^2 failed!",locString);

		//3^3
		src1[0]=3;
		src2[0]=3;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[0]=27;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("3^3 failed!",locString);

		//0:0:1:0^2
		src1[0]=0;
		src1[1]=1;
		src2[0]=2;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		src1[1]=0;
		src1[2]=1;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:0^2 failed!",locString);

		//0:0:1:0^3
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src2[0]=3;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
		//testout<<dest1[3]<<":"<<dest1[2]<<":"<<dest1[1]<<":"<<dest1[0]<<std::endl;
		src1[0]=1;
		src1[1]=4294967295;
		src1[2]=0;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0:0:1:0^3 failed!",locString);

		//0:0:1:0^4
		src1[0]=0;
		src1[1]=1;
		src1[2]=0;
		src1[3]=0;

		src2[0]=4;
		ret=_baseType->moduloExponentiation(src1,src2,modVal,dest1,4);
        if(ret)
            generalTestException::throwException("Overflow failed!",locString);
	}
	//Base 10 GCD test
	void base10GCDTest()
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10GCDTest()";

		uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//0 gcd 0
		ret=_baseType->gcd(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("0 gcd 0 failed!",locString);

		//1 gcd 1
		src1[0]=1;
		src2[0]=1;
		ret=_baseType->gcd(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("1 gcd 1 failed!",locString);

		//2 gcd 4
		src1[0]=2;
		src2[0]=4;
		ret=_baseType->gcd(src1,src2,dest1,4);
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("2 gcd 4 failed!",locString);

		//4 gcd 6
		src1[0]=4;
		src2[0]=6;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=2;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("4 gcd 6 failed!",locString);

		//6 gcd 9
		src1[0]=6;
		src2[0]=9;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("6 gcd 9 failed!",locString);

		//9 gcd 6
		src1[0]=9;
		src2[0]=6;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("9 gcd 6 failed!",locString);

		//9 gcd 6
		src1[0]=9;
		src2[0]=6;
		ret=_baseType->gcd(src1,src2,dest1,4);
		src1[0]=3;
        if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("9 gcd 6 failed!",locString);
	}
	//Base 10 Modular Inverse Test
	void base10ModularInverseTest()
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10ModularInverseTest()";

		uint32_t src1[4];
        uint32_t src2[4];
        uint32_t dest1[4];
        int ret;

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;
        src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]=0;

		//(3 mod 7)^-1
		src1[0]=3;
		src2[0]=7;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=5;
		if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("(3 mod 7)^-1 failed!",locString);

		//(4 mod 97)^-1
		src1[0]=4;
		src2[0]=97;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=73;
		if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("(4 mod 97)^-1 failed!",locString);

		//(300 mod 38897)^-1
		src1[0]=300;
		src2[0]=38897;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=8687;
		if(_baseType->compare(src1,dest1,4)!=0 || !ret)
            generalTestException::throwException("(300 mod 38897)^-1 failed!",locString);

		//(6 mod 8)^-1
		src1[0]=6;
		src2[0]=8;
		ret=_baseType->modInverse(src1,src2,dest1,4);
		src1[0]=1;
		if(_baseType->compare(src1,dest1,4)!=0 || ret)
            generalTestException::throwException("(6 mod 8)^-1 failed!",locString);
	}
	//Base 10 Primality test
	void base10PrimealityTest()
	{
		struct numberType* _baseType = typeCheckBase10();
        std::string locString = "c_cryptoTesting.cpp, base10PrimealityTest()";

		uint32_t src1[4];

        src1[3]=0;  src1[2]=0;  src1[1]=0;  src1[0]=0;

		//0
		if(primeTest(src1,10,4))
			generalTestException::throwException("0 is not prime!",locString);

		//1
		src1[0]=1;
		if(!primeTest(src1,10,4))
			generalTestException::throwException("1 is prime!",locString);

		//2
		src1[0]=2;
		if(!primeTest(src1,10,4))
			generalTestException::throwException("2 is prime!",locString);

		//3
		src1[0]=3;
		if(!primeTest(src1,10,4))
			generalTestException::throwException("3 is prime!",locString);

		//4
		src1[0]=4;
		if(primeTest(src1,10,4))
			generalTestException::throwException("4 is not prime!",locString);

		//5
		src1[0]=5;
		if(!primeTest(src1,10,4))
			generalTestException::throwException("5 is prime!",locString);

		//55
		src1[0]=55;
		if(primeTest(src1,10,4))
			generalTestException::throwException("55 is not prime!",locString);

		//99
		src1[0]=99;
		if(primeTest(src1,10,4))
			generalTestException::throwException("99 is not prime!",locString);

		//401
		src1[0]=401;
		if(!primeTest(src1,10,4))
			generalTestException::throwException("401 is prime!",locString);

		//243407
		src1[0]=243407;
		if(primeTest(src1,10,4))
			generalTestException::throwException("243407 is not prime!",locString);
	}

/*================================================================
	C Test Suites
 ================================================================*/

    //C Base-10 Test Suite
    C_BaseTenSuite::C_BaseTenSuite():
        testSuite("C Base-10")
    {
        pushTest("NULL Number Type",&nullNumberType);
        pushTest("Base-10 Number Type",&typeCheckBase10Test);
        pushTest("Compare",&base10compareTest);
        pushTest("Addition",&base10additionTest);
        pushTest("Subtraction",&base10subtractionTest);
        pushTest("Right Shift",&base10rightShiftTest);
        pushTest("Left Shift",&base10leftShiftTest);
        pushTest("Multiplication",&base10multiplicationTest);
        pushTest("Division",&base10divisionTest);
		pushTest("Modulo",&base10moduloTest);
		pushTest("Exponentiation",&base10exponentiationTest);
		pushTest("Modular Exponentiation",&base10modularExponentiationTest);
		pushTest("GCD",&base10GCDTest);
		pushTest("Modular Inverse",&base10ModularInverseTest);
		pushTest("Prime Testing",&base10PrimealityTest);
    }

#endif

///@endcond