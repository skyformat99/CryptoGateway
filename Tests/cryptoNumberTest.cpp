/**
 * This file has a series of tests which confirm
 * the functionality of crypto::integer and it's
 * base class, crypto::number.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_NUMBER_TEST_CPP
#define CRYPTO_NUMBER_TEST_CPP

#include "cryptoTest.h"
#include "../cryptoNumber.h"

using namespace test;
using namespace os;
using namespace crypto;

/*================================================================
	Number Tests
 ================================================================*/

    //Randomly generate a number
    number generateNumber()
    {
        number ret=integer(8);
        //Size 8
        for(int i=0;i<4;++i)
        {
            ret[i]=rand();
        }
        return ret;
    }

    //Number type test
    void numberTypeTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberTypeTest()";

        number num;

        //Check all types
        if(num.hasCompare())
            generalTestException::throwException("hasCompare failed",locString);
        if(num.hasAddition())
            generalTestException::throwException("hasAddition failed",locString);
        if(num.hasSubtraction())
            generalTestException::throwException("hasSubtraction failed",locString);
        if(num.hasRightShift())
            generalTestException::throwException("hasRightShift failed",locString);
        if(num.hasLeftShift())
            generalTestException::throwException("hasLeftShift failed",locString);
        if(num.hasMultiplication())
            generalTestException::throwException("hasMultiplication failed",locString);
        if(num.hasDivision())
            generalTestException::throwException("hasDivision failed",locString);
        if(num.hasModulo())
            generalTestException::throwException("hasModulo failed",locString);
        if(num.hasExponentiation())
            generalTestException::throwException("hasExponentiation failed",locString);
        if(num.hasModuloExponentiation())
            generalTestException::throwException("hasModuloExponentiation failed",locString);
        if(num.hasGCD())
            generalTestException::throwException("hasGCD failed",locString);
        if(num.hasModInverse())
            generalTestException::throwException("hasModInverse failed",locString);
    }
    //Tests number constructor
    void numberConstructorsTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberConstructorsTest()";

		//Basic
		number num;
		if(num.numberDefinition()==NULL)
			generalTestException::throwException("NULL Number definition: basic",locString);
		if(num.typeID()!=crypto::numberType::Default)
			generalTestException::throwException("Unexpected number type: basic",locString);
		if(num.name()!=std::string(crypto::numberName::Default))
			generalTestException::throwException("Unexpected number name: basic",locString);
		if(num.size()!=1)
			generalTestException::throwException("Unexpected number size: basic",locString);
		if(num.data()[0]!=0)
			generalTestException::throwException("Unexpected number: basic",locString);

		//Size constructor
		number num2(4);
		if(num2.numberDefinition()==NULL)
			generalTestException::throwException("NULL Number definition: size",locString);
		if(num2.typeID()!=crypto::numberType::Default)
			generalTestException::throwException("Unexpected number type: size",locString);
		if(num2.name()!=std::string(crypto::numberName::Default))
			generalTestException::throwException("Unexpected number name: size",locString);
		if(num2.size()!=4)
			generalTestException::throwException("Unexpected number size: size",locString);
		if(num2.data()[3]!=0 || num2.data()[2]!=0 || num2.data()[1]!=0 || num2.data()[0]!=0)
			generalTestException::throwException("Unexpected number: size",locString);

		//Data constructor
		uint32_t a[3];
		a[2]=2;	a[1]=1;	a[0]=0;
		number num3(a,3);
		if(num3.numberDefinition()==NULL)
			generalTestException::throwException("NULL Number definition: data",locString);
		if(num3.typeID()!=crypto::numberType::Default)
			generalTestException::throwException("Unexpected number type: data",locString);
		if(num3.name()!=std::string(crypto::numberName::Default))
			generalTestException::throwException("Unexpected number name: data",locString);
		if(num3.size()!=3)
			generalTestException::throwException("Unexpected number size: data",locString);
		if(num3.data()[2]!=2 || num3.data()[1]!=1 || num3.data()[0]!=0)
			generalTestException::throwException("Unexpected number: data",locString);

		//Copy constructor
		number num4(num3);
		if(num4.numberDefinition()==NULL)
			generalTestException::throwException("NULL Number definition: copy",locString);
		if(num4.typeID()!=crypto::numberType::Default)
			generalTestException::throwException("Unexpected number type: copy",locString);
		if(num4.name()!=std::string(crypto::numberName::Default))
			generalTestException::throwException("Unexpected number name: copy",locString);
		if(num4.size()!=3)
			generalTestException::throwException("Unexpected number size: copy",locString);
		if(num4.data()[2]!=2 || num4.data()[1]!=1 || num4.data()[0]!=0)
			generalTestException::throwException("Unexpected number: copy",locString);

		//Equal constructor
		number num5=num4;
		if(num5.numberDefinition()==NULL)
			generalTestException::throwException("NULL Number definition: equal",locString);
		if(num5.typeID()!=crypto::numberType::Default)
			generalTestException::throwException("Unexpected number type: equal",locString);
		if(num5.name()!=std::string(crypto::numberName::Default))
			generalTestException::throwException("Unexpected number name: equal",locString);
		if(num5.size()!=3)
			generalTestException::throwException("Unexpected number size: equal",locString);
		if(num5.data()[2]!=2 || num5.data()[1]!=1 || num5.data()[0]!=0)
			generalTestException::throwException("Unexpected number: equal",locString);
	}
	//Comparison
	void numberComparisonTest()
	{
		std::string locString = "cryptoNumberTest.cpp, numberComparisonTest()";

		//Raw comparisons
		uint32_t tone,ttwo;
		tone=1;	ttwo=2;
		number num1, num2;

		//==
		num1=number(&tone,1);	num2=number(&tone,1);
		if(!(num1==num2)) generalTestException::throwException("1==1 failed",locString);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(num1==num2) generalTestException::throwException("1==2 succeeded",locString);

		//!=
		num1=number(&tone,1);	num2=number(&tone,1);
		if(num1!=num2) generalTestException::throwException("1!=1 succeeded",locString);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(!(num1!=num2)) generalTestException::throwException("1!=2 failed",locString);

		//>=
		num1=number(&tone,1);	num2=number(&tone,1);
		if(!(num1>=num2)) generalTestException::throwException("1>=1 failed",locString);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(num1>=num2) generalTestException::throwException("1>=2 succeeded",locString);

		//<=
		num1=number(&ttwo,1);	num2=number(&tone,1);
		if(num1<=num2) generalTestException::throwException("1<=1 succeeded",locString);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(!(num1<=num2)) generalTestException::throwException("1<=2 failed",locString);

		//>
		num1=number(&ttwo,1);	num2=number(&tone,1);
		if(!(num1>num2)) generalTestException::throwException("2>1 failed",locString);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(num1>num2) generalTestException::throwException("1>2 succeeded",locString);

		//<
		num1=number(&ttwo,1);	num2=number(&tone,1);
		if(num1<num2) generalTestException::throwException("1<1 succeeded",locString);
		num1=number(&tone,1);	num2=number(&ttwo,1);
		if(!(num1<num2)) generalTestException::throwException("1<2 failed",locString);

		//Double length tests
		uint32_t arr[2];	arr[1]=2;	arr[0]=1;
		number big(arr,2);

		//2:1 != 1
		if(big == num2) generalTestException::throwException("2:1 == 1 succeeded",locString);

		//2:1 > 1
		if(big <= num2) generalTestException::throwException("2:1 <= 1 succeeded",locString);

		//1 < 2:1
		if(num2 >= big) generalTestException::throwException("1 >= 2:1 succeeded",locString);
	}
    //Array access
    void numberArrayAccessTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberArrayAccessTest()";
        uint32_t arr[3];
        arr[2]=0;   arr[1]=3;   arr[0]=5;
        number num(arr,3);

        //Test positions
        if(num[0]!=5 && num[1]!=3)
            generalTestException::throwException("Read access failed!",locString);

        //Overflow
        if(num[2]!=0)
            generalTestException::throwException("Overflow failed: "+std::to_string((long long unsigned int)num[2]),locString);

        //Write access
        num[0]=3;
        num[1]=16;
        if(num[0]!=3 && num[1]!=16)
            generalTestException::throwException("Write access failed!",locString);
    }
    //To string
    void numberToStringTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberToStringTest()";
        number num(4);

        //All zeros
        if(num.toString()!="00000000:00000000:00000000:00000000")
            generalTestException::throwException("Zero case failure",locString);

        //1, 2, 3, 4
        num[0]=1;
        num[1]=2;
        num[2]=3;
        num[3]=4;
        if(num.toString()!="00000004:00000003:00000002:00000001")
            generalTestException::throwException("1, 2, 3, 4 case failure",locString);

        //5, 6, 7, 8
        num[0]=5;
        num[1]=6;
        num[2]=7;
        num[3]=8;
        if(num.toString()!="00000008:00000007:00000006:00000005")
        generalTestException::throwException("5, 6, 7, 8 case failure",locString);

        //9, A, B, C
        num[0]=9;
        num[1]=10;
        num[2]=11;
        num[3]=12;
        if(num.toString()!="0000000C:0000000B:0000000A:00000009")
        generalTestException::throwException("9, A, B, C case failure",locString);

        //D, E, F, 10
        num[0]=13;
        num[1]=14;
        num[2]=15;
        num[3]=16;
        if(num.toString()!="00000010:0000000F:0000000E:0000000D")
        generalTestException::throwException("D, E, F, 10 case failure",locString);

        //11, 12, 13, 14
        num[0]=17;
        num[1]=18;
        num[2]=19;
        num[3]=20;
        if(num.toString()!="00000014:00000013:00000012:00000011")
        generalTestException::throwException("11, 12, 13, 14 case failure",locString);
    }
    //From string
    void numberFromStringTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberFromStringTest()";
        number comp(4);
        number misc;

        //Build 0
        misc.fromString("0");
        if(comp!=misc)
            generalTestException::throwException("Zero build failure",locString);

        //Build 1
        comp[0]=1;
        misc.fromString("1");
        if(comp!=misc)
            generalTestException::throwException("One build failure",locString);

        //4:3:2:1
        comp[3]=4;
        comp[2]=3;
        comp[1]=2;
        comp[0]=1;
        misc.fromString("4:3:2:1");
        if(comp!=misc)
            generalTestException::throwException("4:3:2:1 build failure",locString);

        //8:7:6:5
        comp[3]=8;
        comp[2]=7;
        comp[1]=6;
        comp[0]=5;
        misc.fromString("8:7:6:5");
        if(comp!=misc)
        generalTestException::throwException("8:7:6:5 build failure",locString);

        //C:B:A:9
        comp[3]=12;
        comp[2]=11;
        comp[1]=10;
        comp[0]=9;
        misc.fromString("C:B:A:9");
        if(comp!=misc)
        generalTestException::throwException("C:B:A:9 build failure",locString);

        //10:F:E:D
        comp[3]=16;
        comp[2]=15;
        comp[1]=14;
        comp[0]=13;
        misc.fromString("10:F:E:D");
        if(comp!=misc)
        generalTestException::throwException("10:F:E:D build failure",locString);

        //FFFFFFFF:FFFFFFFF
        comp[3]=0;
        comp[2]=0;
        comp[1]=~0;
        comp[0]=~0;
        misc.fromString("FFFFFFFF:FFFFFFFF");
        if(comp!=misc)
            generalTestException::throwException("FFFFFFFF:FFFFFFFF build failure",locString);

    }
    //Tests size manipulation
    void numberSizeManipulation()
    {
        std::string locString = "cryptoNumberTest.cpp, numberSizeManipulation()";
        number num;

        //Default size
        if(num.size()!=1)
            generalTestException::throwException("Default size incorrect",locString);

        //Expand (1)
        num.expand(3);
        if(num.size()!=3)
            generalTestException::throwException("Expansion 1 failed",locString);
        if(num[2]!=0 || num[1]!=0 || num[0]!=0)
            generalTestException::throwException("Expansion 1 values wrong",locString);

        //Reduce (1)
        num.reduce();
        if(num.size()!=1)
            generalTestException::throwException("Reduce 1 failed, size "+std::to_string((long long unsigned int)num.size())+" value "+num.toString(),locString);
        if(num[0]!=0)
        generalTestException::throwException("Reduce 1 values wrong",locString);

        //Expand (2)
        num.expand(3);
        if(num.size()!=3)
            generalTestException::throwException("Expansion 2 failed",locString);
        num[1]=10;
        if(num[2]!=0 || num[1]!=10 || num[0]!=0)
            generalTestException::throwException("Expansion 2 values wrong",locString);

        //Reduce (2)
        num.reduce();
        if(num.size()!=2)
            generalTestException::throwException("Reduce 2 failed",locString);
        if(num[1]!=10 || num[0]!=0)
            generalTestException::throwException("Reduce 2 values wrong",locString);

        //Expand (3)
        num.expand(3);
        if(num.size()!=3)
        generalTestException::throwException("Expansion 3 failed",locString);
        if(num[2]!=0 || num[1]!=10 || num[0]!=0)
        generalTestException::throwException("Expansion 3 values wrong",locString);
    }

    //OR Test
    void numberORTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberORTest()";

        //Variable size test
        number s1;
        number s2(4);
        number hld;
        number comp(4);
        s1[0]=4;
        s2[0]=1;
        comp[0]=5;
        s2[3]=2;
        comp[3]=2;

        //4 different size tests
        if((s1|s2)!=comp)
            generalTestException::throwException("size comp 1 wrong",locString);
        if((s2|s1)!=comp)
            generalTestException::throwException("size comp 2 wrong",locString);
        hld=s1;
        s1|=s2;
        s2|=hld;
        if(s1!=comp)
            generalTestException::throwException("size comp 3 wrong",locString);
        if(s2!=comp)
            generalTestException::throwException("size comp 4 wrong",locString);

        //Main test
        for(int i=0;i<20;++i)
        {
            number num1=generateNumber();
            number num2=generateNumber();
            number ans1=num1|num2;
            number ans2=num2|num1;
            number ans3(num1);

            for(int i=0;i<ans3.size();++i)
            {
                ans3[i]=num1[i]|num2[i];
            }
            number t=num1;
            num1|=num2;
            num2|=t;

            if(ans1!=ans3)
                generalTestException::throwException("ans1 wrong",locString);
            if(ans2!=ans3)
                generalTestException::throwException("ans2 wrong",locString);
            if(num1!=ans3)
                generalTestException::throwException("num1 wrong",locString);
            if(num2!=ans3)
                generalTestException::throwException("num2 wrong",locString);
        }
    }
    //OR Test
    void numberANDTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberANDTest()";

        //Variable size test
        number s1;
        number s2(4);
        number hld;
        number comp(4);
        s1[0]=6;
        s2[0]=3;
        comp[0]=2;
        s2[3]=2;
        comp[3]=0;

        //4 different size tests
        if((s1&s2)!=comp)
            generalTestException::throwException("size comp 1 wrong",locString);
        if((s2&s1)!=comp)
            generalTestException::throwException("size comp 2 wrong",locString);
        hld=s1;
        s1&=s2;
        s2&=hld;
        if(s1!=comp)
            generalTestException::throwException("size comp 3 wrong",locString);
        if(s2!=comp)
            generalTestException::throwException("size comp 4 wrong",locString);

        //Main test
        for(int i=0;i<20;++i)
        {
            number num1=generateNumber();
            number num2=generateNumber();
            number ans1=num1&num2;
            number ans2=num2&num1;
            number ans3(num1);

            for(int i=0;i<ans3.size();++i)
            {
                ans3[i]=num1[i]&num2[i];
            }
            number t=num1;
            num1&=num2;
            num2&=t;

            if(ans1!=ans3)
                generalTestException::throwException("ans1 wrong",locString);
            if(ans2!=ans3)
                generalTestException::throwException("ans2 wrong",locString);
            if(num1!=ans3)
                generalTestException::throwException("num1 wrong",locString);
            if(num2!=ans3)
                generalTestException::throwException("num2 wrong",locString);
        }
    }
    //XOR Test
    void numberXORTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberANDTest()";

        //Variable size test
        number s1;
        number s2(4);
        number hld;
        number comp(4);
        s1[0]=6;
        s2[0]=3;
        comp[0]=5;
        s2[3]=2;
        comp[3]=2;


        //4 different size tests
        if((s1^s2)!=comp)
            generalTestException::throwException("size comp 1 wrong",locString);
        if((s2^s1)!=comp)
            generalTestException::throwException("size comp 2 wrong",locString);
        hld=s1;
        s1^=s2;
        s2^=hld;
        if(s1!=comp)
            generalTestException::throwException("size comp 3 wrong",locString);
        if(s2!=comp)
            generalTestException::throwException("size comp 4 wrong",locString);

        //Main test
        for(int i=0;i<20;++i)
        {
            number num1=generateNumber();
            number num2=generateNumber();
            number ans1=num1^num2;
            number ans2=num2^num1;
            number ans3(num1);

            for(int i=0;i<ans3.size();++i)
            {
                ans3[i]=num1[i]^num2[i];
            }
            number t=num1;
            num1^=num2;
            num2^=t;

            if(ans1!=ans3)
                generalTestException::throwException("ans1 wrong",locString);
            if(ans2!=ans3)
                generalTestException::throwException("ans2 wrong",locString);
            if(num1!=ans3)
                generalTestException::throwException("num1 wrong",locString);
            if(num2!=ans3)
            {
                testout<<num1<<std::endl;
                testout<<num2<<" == "<<ans3<<std::endl;
                generalTestException::throwException("num2 wrong",locString);
            }
        }
    }
    //Tests negation
    void numberNegateTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberNegateTest()";
        for(int i=0;i<20;++i)
        {
            number t=generateNumber();
            number comp(t);

            if(t!=comp)
                generalTestException::throwException("Initial copy failed",locString);

            t= ~t;
            if(t==comp)
                generalTestException::throwException("Negate equals to prev",locString);

            for(int i=0;i<t.size();++i)
                comp[i]= ~comp[i];

            if(t!=comp)
                generalTestException::throwException("Negate comparison failed",locString);
        }
    }

/*================================================================
	Integer Tests
 ================================================================*/

    //Randomly generate two integers
    void generateIntegers(integer& int1,integer& int2)
    {
        int1=integer(8);
        int2=integer(8);

        //Size 8
        for(int i=0;i<4;++i)
        {
            int1[i]=rand();
            int2[i]=rand();
        }
    }

    //Integer type test
    void integerTypeTest()
    {
        std::string locString = "cryptoNumberTest.cpp, numberTypeTest()";

        integer num;

        //Check all types
        if(!num.hasCompare())
            generalTestException::throwException("hasCompare failed",locString);
        if(!num.hasAddition())
            generalTestException::throwException("hasAddition failed",locString);
        if(!num.hasSubtraction())
            generalTestException::throwException("hasSubtraction failed",locString);
        if(!num.hasRightShift())
            generalTestException::throwException("hasRightShift failed",locString);
        if(!num.hasLeftShift())
            generalTestException::throwException("hasLeftShift failed",locString);
        if(!num.hasMultiplication())
            generalTestException::throwException("hasMultiplication failed",locString);
        if(!num.hasDivision())
            generalTestException::throwException("hasDivision failed",locString);
        if(!num.hasModulo())
            generalTestException::throwException("hasModulo failed",locString);
        if(!num.hasExponentiation())
            generalTestException::throwException("hasExponentiation failed",locString);
        if(!num.hasModuloExponentiation())
            generalTestException::throwException("hasModuloExponentiation failed",locString);
        if(!num.hasGCD())
            generalTestException::throwException("hasGCD failed",locString);
        if(!num.hasModInverse())
            generalTestException::throwException("hasModInverse failed",locString);
        if(!num.checkType())
            generalTestException::throwException("Integer type check failed!",locString);
    }
    //Integer compare test
    void integerCompareTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerCompareTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Basic different size test
        int1.expand(4);
        int2=integer(2);
        int1[3]=2;
        int2[1]=2;
        if(int1<=int2)
            generalTestException::throwException("Size diff: <= failed",locString);
        if(int1.compare(&int2)!=1)
            generalTestException::throwException("Size diff: compare == 1 failed",locString);
        int1[3]=0;
        int2[0]=5;
        int2[1]=2;
        if(int1>=int2)
            generalTestException::throwException("Size diff: >= failed",locString);
        if(int1.compare(&int2)!=-1)
            generalTestException::throwException("Size diff: compare == -1 failed",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            int cpp_ans;
            int c_ans;
            generateIntegers(src1, src2);

            //src1 to src2
            cpp_ans=src1.compare(&src2);
            c_ans=nt->compare(src1.data(),src2.data(),src1.size());

            if(cpp_ans!=c_ans)
                generalTestException::throwException("src1 comp src2 failed",locString);
            if(cpp_ans==0)
            {
                if(!(src1==src2)||src1!=src2)
                    generalTestException::throwException("Random == failure!",locString);
            }
            else if(cpp_ans<0)
            {
                if(!(src1<src2)||src1>=src2)
                    generalTestException::throwException("Random < failure!",locString);
            }
            else
            {
                if(!(src1>src2)||src1<=src2)
                    generalTestException::throwException("Random > failure!",locString);
            }
        }
    }
    //Integer addition test
    void integerAdditionTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerAdditionTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=6;
        int1[3]=4;
        int2=int1+int2;
        int1[0]=6;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;

            //Preform 3 versions
            nt->addition(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.addition(&src2,&ans2);
            ans3=src1+src2;
            src1+=src2;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer subtraction test
    void integerSubtractionTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerSubtractionTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=6;
        int1[0]=8;
        int1[3]=4;
        int2=int1-int2;
        int1[0]=2;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;
            src1[src1.size()/2+1]=1;

            //Preform 3 versions
            nt->subtraction(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.subtraction(&src2,&ans2);
            ans3=src1-src2;
            src1-=src2;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Tests the incrementing and decrementing of an integer
    void integerIncrementTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerIncrementTest()";
        integer int1;
        integer int2;

        int1++;
        int2[0]++;
        if(int1!=int2)
            generalTestException::throwException("Increment fail: 1",locString);

        int2[0]++;
        if(++int1!=int2)
            generalTestException::throwException("Increment fail: 2",locString);

        if(int1++!=int2)
            generalTestException::throwException("Increment fail: 3",locString);
        int2[0]++;

        int1--;
        int2[0]--;
        if(int1!=int2)
            generalTestException::throwException("Decrement fail: 1",locString);

        int2[0]--;
        if(--int1!=int2)
            generalTestException::throwException("Decrement fail: 2",locString);

        if(int1--!=int2)
            generalTestException::throwException("Decrement fail: 3",locString);
        int2[0]--;
    }
    //Integer subtraction test
    void integerRightShiftTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerRightShiftTest()";
        integer int1;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            unsigned rshift=rand()%128;

            generateIntegers(src1, src2);
            ans1=src1;
            src1[src1.size()/2+1]=1;

            //Preform 3 versions
            nt->rightShift(src1.data(),rshift,ans1.data(),src1.size());
            src1.rightShift(rshift,&ans2);
            ans3=src1>>rshift;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
        }
    }
    //Integer left shift test
    void integerLeftShiftTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerLeftShiftTest()";
        integer int1;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            unsigned rshift=rand()%128;

            generateIntegers(src1, src2);
            ans1=src1;
            src1[src1.size()/2+1]=1;

            //Preform 3 versions
            nt->rightShift(src1.data(),rshift,ans1.data(),src1.size());
            src1.rightShift(rshift,&ans2);
            ans3=src1>>rshift;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
        }
    }
    //Integer multiplicaiton test
    void integerMultiplicationTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerMultiplicationTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=2;
        int1[3]=4;
        int2=int1*int2;
        int1[3]=8;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;

            //Preform 3 versions
            nt->multiplication(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.multiplication(&src2,&ans2);
            ans3=src1*src2;
            src1*=src2;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer division test
    void integerDivisionTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerDivisionTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=2;
        int1[3]=6;
        int2=int1/int2;
        int1[3]=3;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;

            //Preform 3 versions
            nt->division(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.division(&src2,&ans2);
            ans3=src1/src2;
            src1/=src2;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer modulo test
    void integerModuloTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerModuloTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=5;
        int1[0]=9;
        int1[3]=4;
        int2=int1%int2;
        int1[3]=0;
        int1[0]=3;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;

            //Preform 3 versions
            nt->modulo(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.modulo(&src2,&ans2);
            ans3=src1%src2;
            src1%=src2;

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer exponentiation test
    void integerExponentiationTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerModuloTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=3;
        int1[1]=3;
        int2=int1.exponentiation(int2);
        int1.expand(4);
        int1[1]=0;
        int1[3]=27;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            src1[3]=0;  src1[2]=0;  src1[1]=0;
            src2[3]=0;  src2[2]=0;  src2[1]=0;  src2[0]%=5;
            ans1=src1;

            //Preform 3 versions
            nt->exponentiation(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.number::exponentiation(&src2,&ans2);
            ans3=src1.exponentiation(src2);
            src1.exponentiationEquals(src2);

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer mod-exponentiation test
    void integerModuloExponentiationTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerModuloExponentiationTest()";
        integer int1;
        integer int2;
        integer int3;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int3[0]=2;
        int2[0]=11;
        int1[1]=4;
        int1[0]=3;
        int2=int1.moduloExponentiation(int2, int3);
        int1[1]=0;
        int1[0]=1;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer src3;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            generateIntegers(src2,src3);
            ans1=src1;

            //Preform 3 versions
            nt->moduloExponentiation(src1.data(),src2.data(),src3.data(),ans1.data(),src1.size());
            src1.number::moduloExponentiation(&src2,&src3,&ans2);
            ans3=src1.moduloExponentiation(src2,src3);
            src1.moduloExponentiationEquals(src2,src3);

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer gcd test
    void integerGCDTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerGCDTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=6;
        int1[3]=4;
        int2=int1.gcd(int2);
        int1[3]=0;
        int1[0]=2;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            generateIntegers(src1, src2);
            ans1=src1;

            //Preform 3 versions
            nt->gcd(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.number::gcd(&src2,&ans2);
            ans3=src1.gcd(src2);
            src1.gcdEquals(src2);

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Integer modInver test
    void integerModInverseTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerModInverseTest()";
        integer int1;
        integer int2;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Quickly test a variable size example
        int1.expand(4);
        int2[0]=17;
        int1[3]=4;
        int1%=int2;
        int2=int1.modInverse(int2);
        int1[3]=0;
        int1[0]=13;
        if(int1!=int2)
            generalTestException::throwException("Variable size failed!",locString);

        //Run compare tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            integer ans1;
            integer ans2;
            integer ans3;
            src1[0]=rand();
            src2[0]=7919;

            //Preform 3 versions
            nt->modInverse(src1.data(),src2.data(),ans1.data(),src1.size());
            src1.number::modInverse(&src2,&ans2);
            ans3=src1.modInverse(src2);
            src1.modInverseEquals(src2);

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
            if(ans1!=ans3)
                generalTestException::throwException("OO operator failed!",locString);
            if(ans1!=src1)
                generalTestException::throwException("Op= failed",locString);
        }
    }
    //Prime test
    void integerPrimeTest()
    {
        std::string locString = "cryptoNumberTest.cpp, integerPrimeTest()";
        integer int1;
        const struct numberType* nt=int1.numberDefinition();

        //Check if the integer target is valid
        if(!int1.checkType())
            generalTestException::throwException("Integer type check failed!",locString);

        //Run prime tests, 20 iterations
        for(int i=0;i<20;++i)
        {
            integer src1;
            integer src2;
            bool ans1;
            bool ans2;
            generateIntegers(src1, src2);

            //Preform 3 versions
            ans1=primeTest(src1.data(),crypto::algo::primeTestCycle,src1.size());
            ans2=src1.prime();

            //ans1 is the ref value
            if(ans1!=ans2)
                generalTestException::throwException("OO function failed!",locString);
        }
    }

/*================================================================
	Number Test suites
 ================================================================*/

    //Basic number test
    BasicNumberTest::BasicNumberTest():
        testSuite("Basic Number")
    {
        pushTest("Type",&numberTypeTest);
        pushTest("Constructor",&numberConstructorsTest);
		pushTest("Comparison",&numberComparisonTest);
        pushTest("[] Operator",&numberArrayAccessTest);
        pushTest("To String",&numberToStringTest);
        pushTest("From String",&numberFromStringTest);
        pushTest("Size Manipulation",&numberSizeManipulation);

        pushTest("OR Operator",&numberORTest);
        pushTest("AND Operator",&numberANDTest);
        pushTest("XOR Operator",&numberXORTest);
        pushTest("Negate Operator",&numberNegateTest);
    }
    //Base-10 number
    IntegerTest::IntegerTest():
        testSuite("Integer")
    {
        pushTest("Type",&integerTypeTest);
        pushTest("Integer Compare",&integerCompareTest);
        pushTest("Addition",&integerAdditionTest);
        pushTest("Subtraction",&integerSubtractionTest);
        pushTest("Increment",&integerIncrementTest);
        pushTest("Right Shift",&integerRightShiftTest);
        pushTest("Left Shift",&integerLeftShiftTest);
        pushTest("Multiplication",&integerMultiplicationTest);
        pushTest("Division",&integerDivisionTest);
        pushTest("Modulo",&integerModuloTest);
        pushTest("Exponentiation",&integerExponentiationTest);
        pushTest("Modulo Exponentiation",&integerModuloExponentiationTest);
        pushTest("GCD",&integerGCDTest);
        pushTest("Modulo Inverse",&integerModInverseTest);
        pushTest("Prime",&integerPrimeTest);
    }

#endif

///@endcond