/**
 * Implements basic large numbers and the
 * more specific large integer.  Consult
 * cryptoNumber.h for details.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_NUMBER_CPP
#define CRYPTO_NUMBER_CPP

#include "cryptoLogging.h"
#include "cryptoNumber.h"
#include "osMechanics/osMechanics.h"

using namespace crypto;

/*================================================================
	Number
 ================================================================*/

    //Default constructor
    number::number(struct numberType* numDef)
    {
        _numDef=numDef;
        _size = 1;
        _data = new uint32_t[1];
        _data[0]=0;
    }
    //Size constructor
    number::number(uint16_t size, struct numberType* numDef)
    {
        _numDef=numDef;
        _size=size;
        if(_size<1)_size=0;

        _data = new uint32_t[_size];
        memset(_data,0,sizeof(uint32_t)*_size);
    }
    //Construct with data
    number::number(const uint32_t* d, uint16_t size, struct numberType* numDef)
    {
        _numDef=numDef;
        _size=size;
        if(_size<1)_size=0;

        _data = new uint32_t[_size];
        if(size<1)
            memset(_data,0,sizeof(uint32_t)*_size);
        else
            memcpy(_data, d, sizeof(uint32_t)*_size);
    }
    //Copy constructor
    number::number(const number& num)
    {
        _numDef=num._numDef;
        _size=num._size;
        _data = new uint32_t[_size];
        memcpy(_data, num._data, sizeof(uint32_t)*_size);
    }
	//Copy number into self
	number& number::operator=(const number& num)
	{
		if(&num!=this)
		{
			delete [] _data;
			_numDef=num._numDef;
			_size=num._size;
			_data = new uint32_t[_size];
			memcpy(_data, num._data, sizeof(uint32_t)*_size);
		}
		return *this;
	}
    //Destructor
    number::~number(){delete [] _data;}

//Size manipulation----------------------------------------------

    //Reduce the size of a number
    void number::reduce()
    {
        uint32_t targ_size = _size;
        for(targ_size=_size-1;targ_size>0 && _data[targ_size]==0;targ_size--){}

        targ_size++;
        if(targ_size==_size) return;

        uint32_t* temp = new uint32_t[targ_size];
        memcpy(temp, _data, sizeof(uint32_t)*targ_size);
        delete [] _data;
        _data =temp;
        _size = targ_size;
    }
    //Expand the size of a number
    void number::expand(uint16_t size)
    {
        //Check size first
        if(size<_size)
        {
            cryptoerr<<"Cannot expand!  Target size is smaller than current size!"<<std::endl;
            return;
        }
        if(size==_size) return;

        //Preform expansion
        uint32_t* temp = new uint32_t[size];
        memset(temp,0,sizeof(uint32_t)*size);
        memcpy(temp, _data, sizeof(uint32_t)*_size);
        delete [] _data;
        _data =temp;
        _size = size;
    }

//Get Data-------------------------------------------------------

	//Return the raw byte data for the number
	os::smart_ptr<unsigned char> number::getCharData(size_t& arr_len) const
	{
		uint32_t targ_size = _size;
        for(targ_size=_size-1;targ_size>0 && _data[targ_size]==0;targ_size--){}

        targ_size++;

		arr_len=targ_size*4;
		os::smart_ptr<unsigned char> ret(new unsigned char[arr_len],os::shared_type_array);
        memset(ret.get(), 0, arr_len);
        memcpy(ret.get(), _data, arr_len);
		return ret;
	}
	//Return a compatibility version of the raw byte data
	os::smart_ptr<unsigned char> number::getCompCharData(size_t& arr_len) const
	{
		uint32_t targ_size = _size;
        for(targ_size=_size-1;targ_size>0 && _data[targ_size]==0;targ_size--){}

        targ_size++;

		arr_len=targ_size*4;
		os::smart_ptr<unsigned char> ret(new unsigned char[arr_len],os::shared_type_array);
		memset(ret.get(), 0, arr_len);
		for(unsigned int i=0;i<targ_size;++i)
		{
			uint32_t swtc=os::to_comp_mode(_data[i]);
			memcpy(ret.get()+i*4,&swtc,4);
		}

		return ret;
	}

//To and from string---------------------------------------------

    //Converts number to string
    std::string number::toString() const
    {
        std::string ret="";
        for(int i=0;i<_size;++i)
        {
            ret=toHex(_data[i])+ret;
            if(i+1<_size)
                ret=':'+ret;
        }
        return ret;
    }
    //Converts string to number
    void number::fromString(const std::string& str)
    {
        //Reset everything
        _size=1;
        delete [] _data;
        uint16_t totLen=1;
        int groupLen=0;

        //Try and determine length
        for(int i=0;i<str.length();++i)
        {
            //Its a hex character
            if(isHexCharacter(str[i]))
            {
                groupLen++;
                if(groupLen>8)
                {
                    cryptoerr<<"Illegal number construction string!"<<std::endl;
                    _data=new uint32_t[_size];
                    memset(_data,0,sizeof(uint32_t)*_size);
                    return;
                }
            }
            //Its a divider
            else if(str[i]==':')
            {
                totLen++;
                groupLen=0;
            }
            //Its neither, illegal string
            else
            {
                cryptoerr<<"Illegal number construction string!"<<std::endl;
                _data=new uint32_t[_size];
                memset(_data,0,sizeof(uint32_t)*_size);
                return;
            }
        }

        //Build target array
        _size=totLen;
        _data=new uint32_t[_size];
        memset(_data,0,sizeof(uint32_t)*_size);
        int strTrace = 0;
        for(uint16_t trc=_size;trc>0 && strTrace<str.length();trc--)
        {
            std::string current="";
            for(;strTrace<str.length() && str[strTrace]!=':';strTrace++)
                current+=str[strTrace];
            strTrace++;
            _data[trc-1]=fromHex32(current);
        }
    }
    //Ostream operator
    std::ostream& crypto::operator<<(std::ostream& os, const number& num)
    {
        os<<num.toString();
        return os;
    }
    //Istream operator
    std::istream& crypto::operator>>(std::istream& is, number& num)
    {
        std::string track="";
        char cur=is.get();
        int charCount=0;
        while(charCount<8 && (cur==':' || isHexCharacter(cur)))
        {
            if(cur==':') charCount=0;
            track+=cur;
            cur=is.get();
        }
        num.fromString(track);
        return is;
    }

//Operator Access------------------------------------------------

	//Return element at position
	uint32_t number::operator[](uint16_t pos) const
	{
		if(pos>_size) return 0;
		return _data[pos];
	}
	//Modify element at position
	uint32_t& number::operator[](uint16_t pos)
	{
		if(pos>_size)
		{
			cryptoerr<<"Position "<<pos<<" is outside of the bounds of size "<<_size<<"!"<<std::endl;
			return _data[0];
		}
		return _data[pos];
	}

//Bitwise operators----------------------------------------------

    //OR operator
    number number::operator|(const number& op) const
    {
        number ret(_size);
        if(ret._size<op._size)
            ret.expand(op._size);

        uint16_t i;
        for(i=0;i<_size && i<op._size;++i)
            ret._data[i]=_data[i]|op._data[i];
        while(i<_size)
        {
            ret._data[i]=_data[i];
            ++i;
        }
        while(i<op._size)
        {
            ret._data[i]=op._data[i];
            ++i;
        }

        return ret;
    }
    //OR equals operator
    number& number::operator|=(const number& op)
    {
        if(_size<op._size)
            expand(op._size);
        for(uint16_t i=0;i<_size && i<op._size;++i)
            _data[i]|=op._data[i];
        return *this;
    }
    //AND operator
    number number::operator&(const number& op) const
    {
        number ret(_size);
        if(ret._size<op._size)
            ret.expand(op._size);

        uint16_t i;
        for(i=0;i<_size && i<op._size;++i)
            ret._data[i]=_data[i]&op._data[i];

        return ret;
    }
    //AND equals operator
    number& number::operator&=(const number& op)
    {
        if(_size<op._size)
            expand(op._size);
        uint16_t i;
        for(i=0;i<_size && i<op._size;++i)
            _data[i]&=op._data[i];
        while(i<_size)
        {
            _data[i]=0;
            ++i;
        }
        return *this;
    }
    //XOR operator
    number number::operator^(const number& op) const
    {
        number ret(_size);
        if(ret._size<op._size)
            ret.expand(op._size);

        uint16_t i;
        for(i=0;i<_size && i<op._size;++i)
            ret._data[i]=_data[i]^op._data[i];
        while(i<_size)
        {
            ret._data[i]=_data[i];
            ++i;
        }
        while(i<op._size)
        {
            ret._data[i]=op._data[i];
            ++i;
        }

        return ret;
    }
    //XOR equals operator
    number& number::operator^=(const number& op)
    {
        if(_size<op._size)
            expand(op._size);
        for(uint16_t i=0;i<_size && i<op._size;++i)
            _data[i]^=op._data[i];
        return *this;
    }
    //Negate
    number number::operator~() const
    {
        number ret(*this);
        for(uint16_t i=0;i<ret.size();++i)
            ret._data[i]= ~ret._data[i];
        return ret;
    }

//Action Functions-----------------------------------------------

    //Raw compare
    int number::compare(const number* n2) const
    {
        //Check NULLs first
        if(this==n2) return 0;
        if(n2==NULL) return 1;

        //Check if our compare function is even defined
        if(!hasCompare())
        {
            return ((long) this) - ((long) n2);
        }

        //See if sizes need to be rectified
        if(_size==n2->_size)
            return _numDef->compare(_data,n2->_data,_size);

        //Rectify sizes
        const number* tn1=this;
        const number* tn2=n2;
        number temp;
        if(tn1->_size>tn2->_size)
        {
            temp=number(tn2->_data,tn2->_size);
            temp.expand(_size);
            tn2=&temp;
        }
        else
        {
            temp=number(_data,_size);
            temp.expand(tn2->_size);
            tn1=&temp;
        }

        return _numDef->compare(tn1->_data,tn2->_data,_size);
    }
    //Addition function
    void number::addition(const number* n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasAddition()||n2==NULL)
        {
            if(!hasAddition()) cryptoerr<<"Called addition when no addition function exists!"<<std::endl;
            else cryptoerr<<"Called addition with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->addition(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Addition error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Subtraction function
    void number::subtraction(const number* n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasSubtraction()||n2==NULL)
        {
            if(!hasSubtraction()) cryptoerr<<"Called subtraction when no subtraction function exists!"<<std::endl;
            else cryptoerr<<"Called subtraction with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->subtraction(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Subtraction error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Right shift function
    void number::rightShift(uint16_t n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasRightShift())
        {
            cryptoerr<<"Called right shift when no right shift function exists!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }

        bool good = _numDef->rightShift(d1,n2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;

        if(!good)
        {
            cryptoerr<<"Right shift error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Left shift function
    void number::leftShift(uint16_t n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasLeftShift())
        {
            cryptoerr<<"Called left shift when no left shift function exists!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }

        bool good = _numDef->leftShift(d1,n2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;

        if(!good)
        {
            cryptoerr<<"Left shift error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Multiplication
    void number::multiplication(const number* n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasMultiplication()||n2==NULL)
        {
            if(!hasMultiplication()) cryptoerr<<"Called multiplication when no multiplication function exists!"<<std::endl;
            else cryptoerr<<"Called multiplication with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->multiplication(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Exponentiation error!"<<std::endl;
            *result=integer();
        }
    }
    //Division
    void number::division(const number* n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasDivision()||n2==NULL)
        {
            if(!hasDivision()) cryptoerr<<"Called division when no division function exists!"<<std::endl;
            else cryptoerr<<"Called division with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->division(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Division error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Modulo function
    void number::modulo(const number* n2, number* result) const
    {
        //Check if our compare function is even defined
        if(!hasModulo()||n2==NULL)
        {
            if(!hasModulo()) cryptoerr<<"Called modulo when no modulo function exists!"<<std::endl;
            else cryptoerr<<"Called modulo with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->modulo(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Modulo error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Exponentiation function
    void number::exponentiation(const number* n2, number* result) const
    {
        //Check if our function is even defined
        if(!hasExponentiation()||n2==NULL)
        {
            if(!hasExponentiation()) cryptoerr<<"Called exponentiation when no exponentiation function exists!"<<std::endl;
            else cryptoerr<<"Called exponentiation with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->exponentiation(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Exponentiation error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Mod exponentiation
    void number::moduloExponentiation(const number* n2, const number* n3, number* result) const
    {
        //Check if our function is even defined
        if(!hasExponentiation()||n2==NULL)
        {
            if(!hasExponentiation()) cryptoerr<<"Called mod exponentiation when no mod exponentiation function exists!"<<std::endl;
            else cryptoerr<<"Called mod exponentiation with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(n3->_size>targ_size) targ_size=n3->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;
        uint32_t* d3=n3->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }
        if(targ_size>n3->_size)
        {
            d3=new uint32_t[targ_size];
            memset(d3,0,sizeof(uint32_t)*targ_size);
            memcpy(d3, n3->_data, sizeof(uint32_t)*n3->_size);
        }

        bool good=true;
        good = _numDef->moduloExponentiation(d1,d2,d3,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;
        if(targ_size>n3->_size) delete [] d3;

        if(!good)
        {
            cryptoerr<<"Mod exponentiation error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Preform GCD operation
    void number::gcd(const number* n2,number* result) const
    {
        //Check if our function is even defined
        if(!hasGCD()||n2==NULL)
        {
            if(!hasGCD()) cryptoerr<<"Called GCD when no GCD function exists!"<<std::endl;
            else cryptoerr<<"Called GCD with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->gcd(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"GCD error!"<<std::endl;
            *result=integer();
        }

        return;
    }
    //Modular inverse
    void number::modInverse(const number* n2, number* result) const
    {
        //Check if our function is even defined
        if(!hasModInverse()||n2==NULL)
        {
            if(!hasModInverse()) cryptoerr<<"Called modInverse when no modInverse function exists!"<<std::endl;
            else cryptoerr<<"Called modInverse with NULL n2!"<<std::endl;
            *result=integer();
            return;
        }

        //Resize and return result
        int targ_size=_size;
        if(n2->_size>targ_size) targ_size=n2->_size;
        if(result->_size>targ_size) targ_size=result->_size;
        result->expand(targ_size);
        uint32_t* d1=_data;
        uint32_t* d2=n2->_data;

        //Build temp hold values
        if(targ_size>_size)
        {
            d1=new uint32_t[targ_size];
            memset(d1,0,sizeof(uint32_t)*targ_size);
            memcpy(d1, _data, sizeof(uint32_t)*_size);
        }
        if(targ_size>n2->_size)
        {
            d2=new uint32_t[targ_size];
            memset(d2,0,sizeof(uint32_t)*targ_size);
            memcpy(d2, n2->_data, sizeof(uint32_t)*n2->_size);
        }

        bool good=true;
        good = _numDef->modInverse(d1,d2,result->_data,targ_size);

        //Delete temp hold values (if we need to)
        if(targ_size>_size) delete [] d1;
        if(targ_size>n2->_size) delete [] d2;

        if(!good)
        {
            cryptoerr<<"Modulo Inverse error!"<<std::endl;
            *result=integer();
        }

        return;
    }

//Comparison functions-------------------------------------------

    //Compare two numbers
    int number::_compare(const number& n2) const
    {
        uint16_t comp_len=_size;

        //Size mis-matches
        if(_size>n2._size)
        {
            comp_len=n2._size;
            for(uint16_t trc=_size;trc>comp_len;trc--)
            {
                if(_data[trc-1]>0) return 1;
            }
        }
        else if(_size<n2._size)
        {
            for(uint16_t trc=n2._size;trc>comp_len;trc--)
            {
                if(n2._data[trc-1]>0) return -1;
            }
        }

        //Matched size
        for(uint16_t trc=comp_len;trc>0;trc--)
        {
            if(_data[trc-1]>n2._data[trc-1]) return 1;
            else if(_data[trc-1]<n2._data[trc-1]) return -1;
        }
        return 0;
    }
    //Equality operator
    const bool number::operator==(const number& comp) const {return _compare(comp)==0;}
    //Not equal operator
    const bool number::operator!=(const number& comp) const {return _compare(comp)!=0;}
    //Less than or equal
    const bool number::operator<=(const number& comp) const {return _compare(comp)!=1;}
    //Greater than or equal
    const bool number::operator>=(const number& comp) const {return _compare(comp)!=-1;}
    //Less than
    const bool number::operator<(const number& comp) const {return _compare(comp)==-1;}
    //Greater than
    const bool number::operator>(const number& comp) const {return _compare(comp)==1;}

/*================================================================
	Number
 ================================================================*/

    //Static
    integer integer::one()
    {
        integer ret;
        ret[0]=1;
        return ret;
    }
	integer integer::two()
	{
        integer ret;
        ret[0]=2;
        return ret;
    }
    //Basic integer constructor
    integer::integer():number(buildBaseTenType()){}
    //Size constructor
    integer::integer(uint16_t size):number(size,buildBaseTenType()){}
    //Data constructor
    integer::integer(const uint32_t* d, uint16_t size):number(d,size,buildBaseTenType()){}
    //Copy constructor
    integer::integer(const integer& num):number(num){}

    //Checks type
    bool integer::checkType() const
    {
        if(!_numDef) return false;

        //Check all types
        if(!hasCompare()) return false;
        if(!hasAddition()) return false;
        if(!hasSubtraction()) return false;
        if(!hasRightShift()) return false;
        if(!hasLeftShift()) return false;
        if(!hasMultiplication()) return false;
        if(!hasDivision()) return false;
        if(!hasModulo()) return false;
        if(!hasExponentiation()) return false;
        if(!hasModuloExponentiation()) return false;
        if(!hasGCD()) return false;
        if(!hasModInverse()) return false;
        return true;
    }

//Operators--------------------------------------------------------

    //Addition operators
    integer integer::operator+(const integer& n) const
    {
        integer ret(_size);
        addition(&n,&ret);
        return ret;
    }
    integer& integer::operator+=(const integer& n)
    {
        addition(&n,this);
        return *this;
    }
    integer& integer::operator++()
    {
        *this+=integer::one();
        return *this;
    }
    integer integer::operator++(int dummy)
    {
        integer ret(*this);
        *this+=integer::one();
        return ret;
    }
    //Subtraction operators
    integer integer::operator-(const integer& n) const
    {
        integer ret(_size);
        subtraction(&n,&ret);
        return ret;
    }
    integer& integer::operator-=(const integer& n)
    {
        subtraction(&n,this);
        return *this;
    }
    integer& integer::operator--()
    {
        *this-=integer::one();
        return *this;
    }
    integer integer::operator--(int dummy)
    {
        integer ret(*this);
        *this-=integer::one();
        return ret;
    }
    //Shift operators
    integer integer::operator>>(unsigned n) const
    {
        integer ret(_size);
        rightShift(n,&ret);
        return ret;
    }
    integer integer::operator<<(unsigned n) const
    {
        integer ret(_size);
        leftShift(n,&ret);
        return ret;
    }
    //Multiplication operators
    integer integer::operator*(const integer& n) const
    {
        integer ret(_size);
        multiplication(&n,&ret);
        return ret;
    }
    integer& integer::operator*=(const integer& n)
    {
        multiplication(&n,this);
        return *this;
    }
    //Division operators
    integer integer::operator/(const integer& n) const
    {
        integer ret(_size);
        division(&n,&ret);
        return ret;
    }
    integer& integer::operator/=(const integer& n)
    {
        division(&n,this);
        return *this;
    }
    //Modulo operators
    integer integer::operator%(const integer& n) const
    {
        integer ret(_size);
        modulo(&n,&ret);
        return ret;
    }
    integer& integer::operator%=(const integer& n)
    {
        modulo(&n,this);
        return *this;
    }
    //Exponentiation operators
    integer integer::exponentiation(const integer& n) const
    {
        integer ret(_size);
        number::exponentiation(&n,&ret);
        return ret;
    }
    integer& integer::exponentiationEquals(const integer& n)
    {
        number::exponentiation(&n,this);
        return *this;
    }
    //Modulo exponentiation operators
    integer integer::moduloExponentiation(const integer& n, const integer& mod) const
    {
        integer ret(_size);
        number::moduloExponentiation(&n,&mod,&ret);
        return ret;
    }
    integer& integer::moduloExponentiationEquals(const integer& n, const integer& mod)
    {
        number::moduloExponentiation(&n,&mod,this);
        return *this;
    }
    //GCD
    integer integer::gcd(const integer& n) const
    {
        integer ret(_size);
        number::gcd(&n,&ret);
        return ret;
    }
    integer& integer::gcdEquals(const integer& n)
    {
        number::gcd(&n,this);
        return *this;
    }
    //Mod inverse
    integer integer::modInverse(const integer& n) const
    {
        integer ret(_size);
        number::modInverse(&n,&ret);
        return ret;
    }
    integer& integer::modInverseEquals(const integer& n)
    {
        number::modInverse(&n,this);
        return *this;
    }
    //Prime testing
    bool integer::prime(uint16_t testVal) const
    {
        return primeTest(_data,testVal,_size);
    }

#endif

///@endcond