/**
 * Implements basic hashing frameworks and
 * the XOR hash.  Note that the XOR hash is
 * not cryptographically secure.  Consult
 * cryptoHash.h for details.
 **/

 ///@cond INTERNAL

#ifndef CRYPTO_HASH_CPP
#define CRYPTO_HASH_CPP

#include "cryptoLogging.h"
#include "cryptoHash.h"
#include "cryptoError.h"
#include <string>
#include <string.h>

using namespace std;
using namespace crypto;

/********************************************************************
    Crypto Hash
 ********************************************************************/

    //Default hash constructor
    crypto::hash::hash(uint16_t algorithm,uint16_t size)
    {
        if(size<0) size=size::hash256;

        _size=size;
        _algorithm=algorithm;
        _data=new unsigned char[_size];
        memset(_data,0,_size*sizeof(unsigned char));
    }
    //Copy construtor
    crypto::hash::hash(const crypto::hash& cpy)
    {
        _size=cpy._size;
        _algorithm=cpy._algorithm;
        _data=new unsigned char[_size];
        memcpy(_data,cpy._data,_size*sizeof(unsigned char));
    }
    //Equality constructor
    crypto::hash& crypto::hash::operator=(const crypto::hash& cpy)
    {
        delete [] _data;
        _size=cpy._size;
        _algorithm=cpy._algorithm;
        _data=new unsigned char[_size];
        memcpy(_data,cpy._data,_size*sizeof(unsigned char));
        return *this;
    }
    //Default destructor
    crypto::hash::~hash()
    {
        delete [] _data;
    }
    //Compares two hashes
    int crypto::hash::compare(const crypto::hash* _comp) const
    {
        if(_algorithm>_comp->_algorithm) return 1;
        else if(_algorithm<_comp->_algorithm) return-1;

        if(_size>_comp->_size) return 1;
        else if(_size<_comp->_size) return-1;

        for(uint16_t i=_size;i>0;i--)
        {
            if(_data[i-1]>_comp->_data[i-1]) return 1;
            else if(_data[i-1]<_comp->_data[i-1]) return -1;
        }
        return 0;
    }

//Operator Access----------------------------------------------------

    //Return value
    unsigned char crypto::hash::operator[](size_t pos) const
    {
        if(pos<0 || pos>=_size)
            return 0;
        return _data[pos];
    }
    //Set value
    unsigned char& crypto::hash::operator[](size_t pos)
    {
        if(pos<0 || pos>=_size)
            return _data[0];
        return _data[pos];
    }
    //Convert hash to string to output
    std::string crypto::hash::toString() const
    {
        std::string ret="";
        for(int i=0;i<_size;++i)
        {
            ret=toHex(_data[i])+ret;
        }
        return ret;
    }
    //Convert the hash from a string
    void crypto::hash::fromString(const std::string& str)
    {
        uint16_t strLen = (uint16_t) str.length();

        //Check length first
        if(strLen==size::hash64*2) _size=size::hash64;
        else if(strLen==size::hash128*2) _size=size::hash128;
        else if(strLen==size::hash256*2) _size=size::hash256;
        else if(strLen==size::hash512*2) _size=size::hash512;
        else
        {
            memset(_data,0,_size);
			throw errorPointer(new customError("Hash Construction","Illegal string for hash construction"),os::shared_type);
            return;
        }
        delete [] _data;
        _data = new unsigned char[_size];

        //Read out string
        uint16_t i=0;
        uint16_t s=(uint16_t) str.length();
        while(i<_size)
        {
            std::string tem="";
            tem+=str[s-2];
            tem+=str[s-1];
            _data[i]=fromHex8(tem);
            ++i;
            s-=2;
        }
    }
    //Output hash in stream
    std::ostream& crypto::operator<<(std::ostream& os, const crypto::hash& num)
    {
        os<<num.toString();
        return os;
    }
    //Input hash from a stream
    std::istream& crypto::operator>>(std::istream& is, crypto::hash& num)
    {
        std::string track="";
        char cur=is.get();
        int charCount=0;
        while(charCount<size::hash512*2 && isHexCharacter(cur))
        {
            track+=cur;
            cur=is.get();
        }
        num.fromString(track);
        return is;
    }

/********************************************************************
    XOR Hash
 ********************************************************************/

    //XOR hash with data and size
    xorHash::xorHash(const unsigned char* data, size_t length, uint16_t size):
        hash(xorHash::staticAlgorithm(),size)
    {
        preformHash(data,length);
    }
    //XOR hash with data (default size)
    xorHash::xorHash(const unsigned char* data, uint16_t size):
        hash(xorHash::staticAlgorithm(),size)
    {
		//Acts as a copy constructor
		memcpy(_data,data,size);
    }
    //Hash function
    void xorHash::preformHash(const unsigned char* data, size_t dLen)
    {
        for(uint32_t i=0;i<dLen;++i)
        {
            _data[i%_size]^=data[i];
        }
    }
#endif

///@endcond
