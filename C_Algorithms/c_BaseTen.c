/**
 * This file implements all of the basic
 * functionality of a base-10 integer.  All
 * integer operations, both basic and otherwise,
 * are implemented in this file.
 *
 */

///@cond INTERNAL

#ifndef C_BASE_TEN_C
#define C_BASE_TEN_C

#include "c_BaseTen.h"

#ifdef __cplusplus
extern "C" {
#endif

    static bool baseTenInit = false;
    static struct numberType _baseTen;

    //Returns the definition of a base Ten number
    struct numberType* buildBaseTenType()
    {
        if(baseTenInit) return &_baseTen;

        _baseTen.typeID = 1;
        _baseTen.name = crypto_numbername_base10;

        _baseTen.compare = &standardCompare;

        _baseTen.addition = &base10Addition;
        _baseTen.subtraction = &base10Subtraction;

        _baseTen.rightShift = &standardRightShift;
        _baseTen.leftShift = &standardLeftShift;

        _baseTen.multiplication = &base10Multiplication;
        _baseTen.division = &base10Division;
		_baseTen.modulo = &base10Modulo;

		_baseTen.exponentiation = &base10Exponentiation;
		_baseTen.moduloExponentiation = &base10ModuloExponentiation;

		_baseTen.gcd = &base10GCD;
		_baseTen.modInverse = &base10ModInverse;

        baseTenInit = true;
        return &_baseTen;
    }

    //Addition
    int base10Addition(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        //Zero return is error
        if(length<=0) return 0;

        //Add to target
        uint64_t carry = 0;
        for(int cnt =0;cnt<length;cnt++)
        {
            uint64_t tm = (uint64_t) src1[cnt] + (uint64_t) src2[cnt] +carry;
            dest[cnt]=(uint32_t)tm;

            if(tm != (uint32_t) tm)
                carry = (uint32_t) (tm>>32);
            else
                carry=0;
        }
        if(carry>0) return 0;

        return 1;
    }
    //Subtraction
    int base10Subtraction(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        //Zero return is error
        if(length<=0) return 0;

        //Subtract src2 from src1 (src1-src2)
        uint64_t borrow = 0;
        for(int cnt=0;cnt<length;cnt++)
        {
            uint32_t t = src1[cnt] - (src2[cnt]+(uint32_t)borrow);
            if((uint64_t)src1[cnt]>=(uint64_t)src2[cnt]+borrow)
                borrow = 0;
            else
                borrow = 1;
			dest[cnt]=t;
        }
        if(borrow>0) return 0;
        return 1;
    }
    //Multiplication
    int base10Multiplication(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;

		int ret = 1;
		uint32_t* temp = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* targ = (uint32_t*) malloc(length*sizeof(uint32_t));

		//Zero the target
		memset(targ,0,sizeof(uint32_t)*length);

		//Preform multiplication
		for(int cnt=0;cnt<length*32;cnt++)
		{
			int bigPos=cnt/32;
			int smallPos=cnt%32;
			if(src1[bigPos]&(1<<smallPos))
			{
				if(!standardLeftShift(src2,cnt,temp,length))
					ret = 0;
				if(!base10Addition(targ,temp,targ,length))
					ret = 0;
			}
		}

		memcpy(dest,targ,sizeof(uint32_t)*length);
		free(targ);
		free(temp);
        return ret;
    }
    //Division
    int base10Division(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
    {
        if(length<=0) return 0;

		//Exit if divide by zero
		int found = 0;
		for(int cnt=0;cnt<length && !found;cnt++)
		{
			if(src2[cnt]!=0)
				found = 1;
		}

		//Zero the target
		uint32_t* targ = (uint32_t*) malloc(length*sizeof(uint32_t));
		memset(targ,0,sizeof(uint32_t)*length);

		if(!found)
		{
			for(int cnt=0;cnt<length;cnt++)
				dest[cnt]=targ[cnt];
			free(targ);
			return 0;
		}

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));

		//Set temp1 to current src1
		for(int cnt =0;cnt<length;cnt++)
			temp1[cnt]=src1[cnt];

		//Find starting position of src1
		int src1_pos=length*32-1;
		found = 0;
		while(src1_pos>=0 && !found)
		{
			if(src1[src1_pos/32] & (1<<(src1_pos%32)))
				found = 1;
			src1_pos--;
		}

		//Find starting position of src2
		int src2_pos=length*32-1;
		found = 0;
		while(src2_pos>=0 && !found)
		{
			if(src2[src2_pos/32] & (1<<(src2_pos%32)))
				found = 1;
			src2_pos--;
		}

		//Found the two starting positions, calculate division
		for(int cnt=src1_pos-src2_pos;cnt>=0;cnt--)
		{
			//Preform shift
			if(!standardLeftShift(src2,cnt,temp2,length))
			{
				//Shouldn't ever get here
				free(temp1);
				free(temp2);
				for(int cnt=0;cnt<length;cnt++)
					dest[cnt]=targ[cnt];
				free(targ);
				return 0;
			}

			//If temp1>=temp2, subtract and bind to output
			if(standardCompare(temp1,temp2,length)>=0)
			{
				targ[cnt/32]=targ[cnt/32] | (1<<(cnt%32));
				base10Subtraction(temp1,temp2,temp1,length);

			}
		}

		free(temp1);
		free(temp2);

		memcpy(dest,targ,sizeof(uint32_t)*length);
		free(targ);
        return 1;
    }
	//Modulo
	int base10Modulo(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		if(length<=0) return 0;

		//Exit if divide by zero
		int found = 0;
		for(int cnt=0;cnt<length && !found;cnt++)
		{
			if(src2[cnt]!=0)
				found = 1;
		}

		if(!found)
		{
			//Zero the target
			memset((void*) dest,0,sizeof(uint32_t)*length);
			return 0;
		}

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));

		//Set temp1 to current src1
		memcpy(temp1,src1,sizeof(uint32_t)*length);

		//Find starting position of src1
		int src1_pos=length*32-1;
		found = 0;
		while(src1_pos>=0 && !found)
		{
			if(src1[src1_pos/32] & (1<<(src1_pos%32)))
				found = 1;
			src1_pos--;
		}

		//Find starting position of src2
		int src2_pos=length*32-1;
		found = 0;
		while(src2_pos>=0 && !found)
		{
			if(src2[src2_pos/32] & (1<<(src2_pos%32)))
				found = 1;
			src2_pos--;
		}

		//Found the two starting positions, calculate division
		for(int cnt=src1_pos-src2_pos;cnt>=0;cnt--)
		{
			//Preform shift
			if(!standardLeftShift(src2,cnt,temp2,length))
			{
				//Shouldn't ever get here
                memset(dest,0,sizeof(uint32_t)*length);
				free(temp1);
				free(temp2);
				return 0;
			}

			//If temp1>=temp2, subtract and bind to output
			if(standardCompare(temp1,temp2,length)>=0)
				base10Subtraction(temp1,temp2,temp1,length);
		}

		//Copy from temp into destination
		memcpy(dest,temp1,sizeof(uint32_t)*length);

		free(temp1);
		free(temp2);
        return 1;
	}
	//Exponentiation
	int base10Exponentiation(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		//Zero return is error
        if(length<=0) return 0;

		//Check if src1 is zero
		int cnt=0;
		for(cnt=0;cnt<length && src1[cnt]==0;cnt++)
		{}
		if(cnt==length && src1[cnt-1]==0)
		{
			memset((void*) dest,0,sizeof(uint32_t)*length);
			return 1;
		}

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));

		//Zero
		memset((void*) temp1,0,sizeof(uint32_t)*length);
		memcpy((void*) temp2,src1,sizeof(uint32_t)*length);
		temp1[0]=1;

		int cur_state=1;
		int ret_state=1;
		for(cnt=0;cnt<32*length && ret_state;cnt++)
		{
			int bigPos=cnt/32;
			int smallPos=cnt%32;
			if(src2[bigPos]&(1<<smallPos))
			{
				if(!cur_state || !base10Multiplication(temp1,temp2,temp1,length))
					ret_state=0;
			}
			cur_state=base10Multiplication(temp2,temp2,temp2,length);
		}

		memcpy((void*) dest,temp1,sizeof(uint32_t)*length);
		free(temp1);
		free(temp2);

		return ret_state;
	}
	//Modulo exponentiation
	int base10ModuloExponentiation(const uint32_t* src1, const uint32_t* src2,const uint32_t* src3, uint32_t* dest, uint16_t length)
	{
		//Zero return is error
        if(length<=0) return 0;

		//Exit if divide by zero
		int found = 0;
		for(int cnt=0;cnt<length && !found;cnt++)
		{
			if(src3[cnt]!=0)
				found = 1;
		}
		if(!found)
		{
			//Zero the target
			memset((void*) dest,0,sizeof(uint32_t)*length);
			return 0;
		}

		//Check if src1 is zero
		int cnt=0;
		for(cnt=0;cnt<length && src1[cnt]==0;cnt++)
		{}
		if(cnt==length && src1[cnt-1]==0)
		{
			memset((void*) dest,0,sizeof(uint32_t)*length);
			return 1;
		}

		uint32_t* temp1 = (uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp2 = (uint32_t*) malloc(length*sizeof(uint32_t));

		//Zero
		memset((void*) temp1,0,sizeof(uint32_t)*length);
		memcpy((void*) temp2,src1,sizeof(uint32_t)*length);
		temp1[0]=1;

		int cur_state=1;
		int ret_state=1;
		for(cnt=0;cnt<32*length && ret_state;cnt++)
		{
			int bigPos=cnt/32;
			int smallPos=cnt%32;
			if(src2[bigPos]&(1<<smallPos))
			{
				if(!cur_state || !base10Multiplication(temp1,temp2,temp1,length))
					ret_state=0;
				base10Modulo(temp1,src3,temp1,length);
			}
			cur_state=base10Multiplication(temp2,temp2,temp2,length);
			base10Modulo(temp2,src3,temp2,length);
		}

		memcpy((void*) dest,temp1,sizeof(uint32_t)*length);
		free(temp1);
		free(temp2);

		return ret_state;
	}
	//GCD
	int base10GCD(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		if(length<=0) return 0;
		uint32_t* atrace=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* btrace=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* ttrace=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* zero=(uint32_t*) malloc(length*sizeof(uint32_t));

		memcpy(atrace,src1,length*sizeof(uint32_t));
		memcpy(btrace,src2,length*sizeof(uint32_t));
		memset((void*) zero,0,sizeof(uint32_t)*length);

		while(standardCompare(btrace,zero,length)!=0)
		{
			memcpy(ttrace,btrace,length*sizeof(uint32_t));
			if(!base10Modulo(atrace,btrace,btrace,length))
			{
				free(atrace);
				free(btrace);
				free(ttrace);
				free(zero);
				memset((void*) dest,0,sizeof(uint32_t)*length);
				dest[0]=1;
				return 0;
			}
			memcpy(atrace,ttrace,length*sizeof(uint32_t));
		}

		memcpy(dest,atrace,length*sizeof(uint32_t));

		free(atrace);
		free(btrace);
		free(ttrace);
		free(zero);

		return 1;
	}
	//Modular inverse
	int base10ModInverse(const uint32_t* src1, const uint32_t* src2, uint32_t* dest, uint16_t length)
	{
		if(length<=0) return 0;

		//Check GCD first
		uint32_t* one=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* newr=(uint32_t*) malloc(length*sizeof(uint32_t));
        uint32_t* r=(uint32_t*) malloc(length*sizeof(uint32_t));
        uint32_t* newt =(uint32_t*) malloc(length*sizeof(uint32_t));

		memset(one,0,length*sizeof(uint32_t));
        memset(r,0,length*sizeof(uint32_t));

        memcpy(r,src2,length*sizeof(uint32_t));

        int algoStatus=base10Modulo(src1,src2,newr,length);
		one[0]=1;
		if(!base10GCD(newr,src2,newt,length) || standardCompare(newt,one,length)!=0)
		{
			memcpy(dest,one,length*sizeof(uint32_t));
			free(one);
			free(newr);
            free(r);
            free(newt);
			return 0;
		}

		uint32_t* zero=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* t=(uint32_t*) malloc(length*sizeof(uint32_t));

		memset(zero,0,length*sizeof(uint32_t));
		memset(t,0,length*sizeof(uint32_t));

		memcpy(newt,one,length*sizeof(uint32_t));

		uint32_t* quotient=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* hld=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* temp=(uint32_t*) malloc(length*sizeof(uint32_t));

		while(standardCompare(newr,zero,length)!=0 && algoStatus)
		{
			algoStatus&=base10Division(r,newr,quotient,length);

			memcpy(temp,newt,length*sizeof(uint32_t));
			algoStatus&=base10Multiplication(quotient,newt,hld,length);
			algoStatus&=base10Modulo(hld,src2,hld,length);
			if(standardCompare(t,hld,length)==-1)
				algoStatus&=base10Addition(t,src2,t,length);
			algoStatus&=base10Subtraction(t,hld,newt,length);
			memcpy(t,temp,length*sizeof(uint32_t));

			memcpy(temp,newr,length*sizeof(uint32_t));
			algoStatus&=base10Multiplication(quotient,newr,hld,length);
			algoStatus&=base10Modulo(hld,src2,hld,length);
			if(standardCompare(r,hld,length)==-1)
				algoStatus&=base10Addition(r,src2,r,length);
			algoStatus&=base10Subtraction(r,hld,newr,length);
			memcpy(r,temp,length*sizeof(uint32_t));

			algoStatus&=base10Modulo(t,src2,t,length);
		}

		if(!algoStatus)
			memcpy(dest,one,length*sizeof(uint32_t));
		else
			memcpy(dest,t,length*sizeof(uint32_t));

		//Free all the temps
		free(one);
		free(newr);

		free(zero);
		free(t);
		free(r);
		free(newt);

		free(quotient);
		free(hld);
		free(temp);

		return algoStatus;
	}

	//Tests if a number is prime
	int primeTest(const uint32_t* src1, uint16_t test_iteration, uint16_t length)
	{
		if(length<=0) return 0;
		if(test_iteration<=2) return 0;

		int trace = 1;
		int flag = 0;
		int algoStatus = 1;

		//Check for zero set
		while(!flag && trace<length)
		{
			if(src1[trace]!=0)
				flag = 1;
			trace++;
		}

		//Check 0th element
		if(!flag)
		{
			if(src1[0] == 0) return 0;
			if(src1[0] == 1) return 1;
			if(src1[0]==2) return 1;
			if(src1[0]==3) return 1;
		}

		//Check for even case
		if(!(src1[0]&1)) return 0;

		//Miller-Rabin Test
		uint32_t* one=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* minusOne=(uint32_t*) malloc(length*sizeof(uint32_t));

		memset(one,0,length*sizeof(uint32_t));
		one[0]=1;
		algoStatus&=base10Subtraction(src1,one,minusOne,length);

		//Find "d"
		trace = 0;
		flag = 0;
		while(!flag && algoStatus)
		{
			trace++;
			if(minusOne[trace/32]&(1<<(trace%32))) flag = 1;
			if(trace+1>length*32)
				algoStatus=0;
		}

		uint32_t* x=(uint32_t*) malloc(length*sizeof(uint32_t));
		uint32_t* d=(uint32_t*) malloc(length*sizeof(uint32_t));
		algoStatus&=standardLeftShift(minusOne,trace,d,length);
		uint32_t* test=(uint32_t*) malloc(length*sizeof(uint32_t));
		int s=trace;
		int cnt=0;

		//Preform the test
		srand((unsigned)time(NULL));
		while(cnt<test_iteration && algoStatus)
		{
			if(cnt==0) test[0]=2;
			else if(cnt == 1) test[0]=3;
			else
			{
				//Randomly select a test number
				trace=length;
				flag=0;

				while(trace>0 && algoStatus)
				{
					trace--;
					if(flag)
						test[trace]=rand()^(rand()<<1);
					else
						test[trace]=0;
					if(src1[trace]!=0&&!flag)
					{
						flag=1;
						test[trace] = (rand()^(rand()<<1))%src1[trace];
					}
				}
				if(test[0]<3)
					test[0]=3;
			}
			algoStatus&=base10ModuloExponentiation(test,d,src1,x,length);
			if(standardCompare(x,one,length)!=0 && standardCompare(x,minusOne,length))
			{
				flag=0;
				trace=1;
				while(trace<s&&!flag&&algoStatus)
				{
					algoStatus&=base10Multiplication(x,x,x,length);
					algoStatus&=base10Modulo(x,src1,x,length);

					if(algoStatus&&standardCompare(x,one,length)==0)
						algoStatus=0;
					if(algoStatus&&standardCompare(x,minusOne,length)==0)
						flag=1;

					trace++;
				}
				if(!flag) algoStatus=0;
			}
			cnt++;
		}

		free(x);
		free(one);
		free(minusOne);
		free(d);
		free(test);

		return algoStatus;
	}

#ifdef __cplusplus
}
#endif

#endif

///@endcond