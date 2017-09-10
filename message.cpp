/**
 * Implements the message used by
 * the crypto-gateway to pass encrypted
 * data between machines.
 *
 */

///@cond INTERNAL

#ifndef MESSAGE_CPP
#define MESSAGE_CPP

#include "message.h"
#include "cryptoError.h"

#define MAX_EXM 500
namespace crypto {

	//Build an encrypted message from raw data
	message message::encryptedMessage(uint8_t* rawData,size_t sz)
	{
		message ret(sz);
		memcpy(ret.data(),rawData,sz);
		if(rawData[0]==message::BLOCKED || rawData[0]==message::PING ||
			rawData[0]==message::STREAM_KEY || rawData[0]==message::CONFIRM_ERROR ||
			rawData[0]==message::BASIC_ERROR ||
			rawData[0]==message::TIMEOUT_ERROR || rawData[0]==message::PERMENANT_ERROR)
		{
			ret._messageSize=ret._messageSize-1;
		}
		else
		{
			ret._encryptionDepth=rawData[1];
			ret._messageSize=ret._messageSize-3;
		}
		return ret;
	}
	//Build a decrypted message from raw data
	message message::decryptedMessage(uint8_t* rawData,size_t sz)
	{
		message ret(sz);
		return ret;
	}
	//Default message constructor
	message::message(size_t sz)
	{
		if(sz<1) throw errorPointer(new bufferSmallError(),os::shared_type);
		_data=new uint8_t[sz];
		memset(_data,0,sz);
		_size=sz;
		_messageSize=sz-1;
		_encryptionDepth=0;
	}
	//Copy constructor
	message::message(const message& msg)
	{
		_data=new uint8_t[msg._size];
		memcpy(_data,msg._data,msg._size);
		_size=msg._size;
		_messageSize=msg._messageSize;
		_encryptionDepth=msg._encryptionDepth;
	}
	//Add string to to the message
	bool message::pushString(std::string s)
	{
		if(encrypted()) return false;

		//Bound checks
		if(s.length()>255)
		{
			cryptoerr<<"String length greater than allowed!  Returning true to exit logic"<<std::endl;
			return true;
		}
		if(_size+s.length()+1>MAX_EXM)
			return false;
		size_t old_len = _size;

		uint8_t* tdat=_data;
		tdat=new uint8_t[_size+s.length()+1];

		memcpy(tdat,_data,_size);
		memcpy(tdat+_size,s.c_str(),s.length());

		tdat[_size+s.length()]=(uint8_t)s.length();
		delete [] _data;
		_data=tdat;
		_size=(uint16_t) (_size+s.length()+1);
		_messageSize=(uint16_t) (_messageSize+s.length()+1);
		return true;
	}
	//Remove string from message
	std::string message::popString()
	{
		if(encrypted()) return "";

		int strLen=_data[_size-1];
		_data[_size-1]=0;
		if(strLen+1>_size) return "";

		_size=_size-(strLen+1);
		_messageSize=_messageSize-(strLen+1);
		return std::string((char*)_data+_size);
	}
}

#endif

///@endcond
