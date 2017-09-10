/**
 * Contains implementation of the generalized
 * public key and the RSA public key.  Consult
 * cryptoPublicKey.h for details.
 *
 */

///@cond INTERNAL

#ifndef CRYPTO_PUBLIC_KEY_CPP
#define CRYPTO_PUBLIC_KEY_CPP

#include "cryptoPublicKey.h"
#include "cryptoError.h"
#include "binaryEncryption.h"

using namespace crypto;

/*------------------------------------------------------------
     Public Key Frame
 ------------------------------------------------------------*/

	//Public key constructor (with size and algorithm)
	publicKey::publicKey(uint16_t algo,uint16_t sz)
	{
		_algorithm=algo;
		_size=sz;
        _history=10;

		_key=NULL;
		_keyLen=0;
		_fileName="";
	}
    //Copy public key
    publicKey::publicKey(const publicKey& ky)
    {
		_algorithm=ky._algorithm;
        _size=ky._size;
        _history=10;
        _fileName="";
		_timestamp=ky._timestamp;

        //Copy encryption key
        if(ky._key==NULL)
        {
            _key=NULL;
            _keyLen=NULL;
        }
        else
        {
            _key=new unsigned char[ky._keyLen];
            _keyLen=ky._keyLen;
            memcpy(_key,ky._key,_keyLen);
        }
    }
    //Public key constructor
	publicKey::publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t algo,uint16_t sz,uint64_t tms)
	{
		if(!_n || !_d) throw errorPointer(new customError("NULL Keys","Attempted to bind NULL keys to a public key frame"),os::shared_type);
		if(_n->size()!=sz || _d->size()!=sz) throw errorPointer(new customError("Key Size Error","Attempted to bind keys of wrong size"),os::shared_type);
		_algorithm=algo;
		_size=sz;
		_history=10;
		_timestamp=tms;

		_key=NULL;
		_keyLen=0;
		_fileName="";
	}
	//Password constructor
	publicKey::publicKey(uint16_t algo,std::string fileName,std::string password,os::smart_ptr<streamPackageFrame> stream_algo)
	{
		if(fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);
		_algorithm=algo;
		_size=0;
        _history=10;
		_fileName=fileName;

		_key=NULL;
		_keyLen=0;

		setPassword(password);
		setEncryptionAlgorithm(stream_algo);
	}
	//Password constructor
	publicKey::publicKey(uint16_t algo,std::string fileName,unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> stream_algo)
	{
		if(fileName=="") throw errorPointer(new fileOpenError(),os::shared_type);
		_algorithm=algo;
		_size=0;
        _history=10;
		_fileName=fileName;

		_key=NULL;
		_keyLen=0;

		setPassword(key,keyLen);
		setEncryptionAlgorithm(stream_algo);
	}
	//Destructor
	publicKey::~publicKey() throw()
	{
		if(_key) delete [] _key;
	}

	//Find key by hash
	bool publicKey::searchKey(hash hsh, size_t& hist,bool& type)
	{
		os::smart_ptr<streamPackageFrame> hsFrame=streamPackageTypeBank::singleton()->findStream(algo::streamRC4,hsh.algorithm());
		if(!hsFrame) return false;
		hsFrame=hsFrame->getCopy();
		hsFrame->setHashSize(hsh.size());

		//Default D case
		size_t dLen;
		os::smart_ptr<unsigned char> dataChar=d->getCompCharData(dLen);
		if(hsh==hsFrame->hashData(dataChar.get(),dLen))
		{
			hist=CURRENT_INDEX;
			type=PRIVATE;
			return true;
		}

		//Default N case
		dataChar=n->getCompCharData(dLen);
		if(hsh==hsFrame->hashData(dataChar.get(),dLen))
		{
			hist=CURRENT_INDEX;
			type=PUBLIC;
			return true;
		}

        //Search private key history
		unsigned int histTrc=0;
        for(auto trc=oldD.first();trc;++trc)
		{
			dataChar=trc->getCompCharData(dLen);
			if(hsh==hsFrame->hashData(dataChar.get(),dLen))
			{
				hist=histTrc;
				type=PRIVATE;
				return true;
			}
			histTrc++;
		}

		//Search public key history
		histTrc=0;
        for(auto trc=oldN.first();trc;++trc)
		{
			dataChar=trc->getCompCharData(dLen);
			if(hsh==hsFrame->hashData(dataChar.get(),dLen))
			{
				hist=histTrc;
				type=PUBLIC;
				return true;
			}
			histTrc++;
		}

		return false;
	}
	//Find key by value
	bool publicKey::searchKey(os::smart_ptr<number> key, size_t& hist,bool& type)
	{
		//Default D case
		if(*key==*d)
		{
			hist=CURRENT_INDEX;
			type=PRIVATE;
			return true;
		}

		//Default N case
		if(*key==*n)
		{
			hist=CURRENT_INDEX;
			type=PUBLIC;
			return true;
		}

        //Search private key history
		unsigned int histTrc=0;
        for(auto trc=oldD.first();trc;++trc)
		{
			if(*key == *trc)
			{
				hist=histTrc;
				type=PRIVATE;
				return true;
			}
			histTrc++;
		}

		//Search public key history
		histTrc=0;
        for(auto trc=oldN.first();trc;++trc)
		{
			if(*key == *trc)
			{
				hist=histTrc;
				type=PUBLIC;
				return true;
			}
			histTrc++;
		}

		return false;
	}

	//Add a key pair to this public key bank
	void publicKey::addKeyPair(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint64_t tms)
	{
		pushOldKeys(n,d,_timestamp);
		n=copyConvert(_n);
		d=copyConvert(_d);
		_timestamp=tms;
	}

    //Static copy/convert
    os::smart_ptr<number> publicKey::copyConvert(const os::smart_ptr<number> num,uint16_t size)
    {
        os::smart_ptr<number> ret(new number(*num),os::shared_type);
        ret->expand(size*2);
        return ret;
    }
    //Static copy/convert
    os::smart_ptr<number> publicKey::copyConvert(const uint32_t* arr,size_t len,uint16_t size)
    {
		os::smart_ptr<number> ret;
		if(arr==NULL)
			ret=os::smart_ptr<number>(new number(),os::shared_type);
		else
			ret=os::smart_ptr<number>(new number(arr,(uint16_t)len),os::shared_type);
        ret->expand(size*2);
        return ret;
    }
    //Static copy/convert
    os::smart_ptr<number> publicKey::copyConvert(const unsigned char* arr,size_t len,uint16_t size)
    {
        uint32_t* dumpArray=new uint32_t[len/4+1];
        memset(dumpArray,0,4*(len/4+1));
        memcpy(dumpArray,arr,len);
        for(unsigned int i=0;i<len/4+1;++i)
            dumpArray[i]=os::from_comp_mode(dumpArray[i]);
        os::smart_ptr<number> ret=publicKey::copyConvert(dumpArray,len/4+1,size);
        delete [] dumpArray;
        return ret;
    }

    //Copy convert
    os::smart_ptr<number> publicKey::copyConvert(const os::smart_ptr<number> num) const
    {return publicKey::copyConvert(num,_size);}
	//Copy convert
    os::smart_ptr<number> publicKey::copyConvert(const uint32_t* arr,size_t len) const
    {return publicKey::copyConvert(arr,len,_size);}
	//Copy convert for raw byte array
	os::smart_ptr<number> publicKey::copyConvert(const unsigned char* arr,size_t len) const
    {return publicKey::copyConvert(arr,len,_size);}

	//Compare two public keys (by size and algorithm)
	int publicKey::compare(const publicKey& cmp) const
	{
		if(_algorithm>cmp._algorithm) return 1;
		else if(_algorithm<cmp._algorithm) return -1;
		if(_size>cmp._size) return 1;
		else if(_size<cmp._size) return -1;
		return 0;
	}

//History Management-------------------------------------------

    //Push the old keys
    void publicKey::pushOldKeys(os::smart_ptr<number> n, os::smart_ptr<number> d,uint64_t ts)
    {
        if(!n || !d) return;
        if(_history==0) return;
        oldN.insert(n);
        oldD.insert(d);
		_timestamps.insert(os::smart_ptr<uint64_t>(new uint64_t(ts),os::shared_type));

        //Remove extra n and d
        while(oldN.size()>_history)
            oldN.remove(&oldN.last());
        while(oldD.size()>_history)
            oldD.remove(&oldD.last());
		while(_timestamps.size()>_history)
            _timestamps.remove(&_timestamps.last());
        markChanged();
    }
    //Set the history length
    void publicKey::setHistory(size_t hist)
    {
        if(hist>20) return; //Can't keep track of more than 20 at a time
        if(hist<_history)
        {
            //Remove extra n and d
            while(oldN.size()>_history)
				oldN.remove(&oldN.last());
			while(oldD.size()>_history)
				oldD.remove(&oldD.last());
			while(_timestamps.size()>_history)
				_timestamps.remove(&_timestamps.last());
        }
        _history=hist;
		markChanged();
    }

//Access and Generation----------------------------------------

	//Return 'N'
	os::smart_ptr<number> publicKey::getN() const
	{
		if(!n) return NULL;
		return copyConvert(n);
	}
	//Return 'D'
	os::smart_ptr<number> publicKey::getD() const
	{
		if(!d) return NULL;
		return copyConvert(d);
	}
	//Return the old N
	os::smart_ptr<number> publicKey::getOldN(size_t history)
	{
		if(history==CURRENT_INDEX) return getN();
		if(history>=oldN.size()) return NULL;

		readLock();
		auto trc=oldN.first();
		for(unsigned int i=0;i<history&&trc;++i)
		{
			++trc;
		}
		readUnlock();

		if(!trc) return NULL;
		return copyConvert(&trc);
	}
	//Return the old D
	os::smart_ptr<number> publicKey::getOldD(size_t history)
	{
		if(history==CURRENT_INDEX) return getN();
		if(history>=oldD.size()) return NULL;

		readLock();
		auto trc=oldD.first();
		for(unsigned int i=0;i<history&&trc;++i)
		{
			++trc;
		}
		readUnlock();

		if(!trc) return NULL;
		return copyConvert(&trc);
	}
	//Return an old timestamp
	uint64_t publicKey::getOldTimestamp(size_t history)
	{
		if(history==CURRENT_INDEX) return timestamp();
		if(history>=_timestamps.size()) return NULL;

		readLock();
		auto trc=_timestamps.first();
		for(unsigned int i=0;i<history&&trc;++i)
		{
			++trc;
		}
		readUnlock();

		if(!trc) return NULL;
		return *(&trc);
	}
	//Generate a new key
	void publicKey::generateNewKeys()
	{
		writeLock();
		if(n && d) pushOldKeys(n,d,_timestamp);

		n=os::smart_ptr<number>(new number(),os::shared_type);
		d=os::smart_ptr<number>(new number(),os::shared_type);
		_timestamp=os::getTimestamp();

		n->expand(2*_size);
		d->expand(2*_size);
		writeUnlock();

		readLock();
		keyChangeSender::triggerEvent();
		readUnlock();
        markChanged();
	}

//File loading and saving-------------------------------------

	//Save file
	void publicKey::save()
	{
		if(generating()) return;

        readLock();
		if(_fileName=="")
        {
            readUnlock();
            errorSaving("Failed to open file");
            throw errorPointer(new fileOpenError(),os::shared_type);
        }

		//Fine encryption type
		os::smart_ptr<binaryEncryptor> ben;

		if(_key==NULL || _keyLen==0) ben=os::smart_ptr<binaryEncryptor>(new binaryEncryptor(_fileName,"default"),os::shared_type);
		else ben=os::smart_ptr<binaryEncryptor>(new binaryEncryptor(_fileName,_key,_keyLen,fePackage),os::shared_type);

		//If the write failed, throw flag
        if(!ben->good())
        {
            readUnlock();
            errorSaving("Write failed");
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }

		os::smart_ptr<unsigned char>dumpArray(new unsigned char[2*4*_size],os::shared_type_array);
		uint16_t dumpVal;

		//Write size and algorithm
		dumpVal=os::to_comp_mode(_size);
		memcpy(dumpArray.get(),&dumpVal,2);
		dumpVal=os::to_comp_mode(algorithm());
		memcpy(dumpArray.get()+2,&dumpVal,2);
		ben->write(dumpArray.get(),4);

		//Write out timestamp
		uint64_t tsTemp=os::to_comp_mode(_timestamp);
		ben->write((unsigned char*)&tsTemp,8);

		//Write keys
		uint32_t ldval;
		for(unsigned int i1=0;i1<2;i1++)
		{
			os::smart_ptr<number> t;
			if(i1==0) t=n;
			else t=d;
			for(unsigned int i2=0;i2<_size;i2++)
			{
				ldval=os::to_comp_mode(t->data()[i2]);
				memcpy(dumpArray.get()+i1*4*_size+i2*4,&ldval,4);
			}
		}
		ben->write(dumpArray.get(),2*4*_size);

		//If the write failed, throw flag
		if(!ben->good())
        {
            readUnlock();
            errorSaving("Write failed");
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }

        //Old n and d's
        dumpVal=os::to_comp_mode((uint16_t)_history);
        memcpy(dumpArray.get(),&dumpVal,2);
        ben->write(dumpArray.get(),2);
        if(!ben->good())
        {
            readUnlock();
            errorSaving("Write failed");
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }

        auto ntrc=oldN.last();
        auto dtrc=oldD.last();
		auto ttrc=_timestamps.last();
        while(ntrc && dtrc && ttrc)
        {
			tsTemp=os::to_comp_mode(*ttrc);
			ben->write((unsigned char*)&tsTemp,8);

            for(unsigned int i1=0;i1<2;i1++)
            {
                os::smart_ptr<number> t;
                if(i1==0) t=&ntrc;
                else t=&dtrc;
                for(unsigned int i2=0;i2<_size;i2++)
                {
                    ldval=os::to_comp_mode(t->data()[i2]);
                    memcpy(dumpArray.get()+i1*4*_size+i2*4,&ldval,4);
                }
            }
            ben->write(dumpArray.get(),2*4*_size);

            //Go to the next n and d
            if(!ben->good())
            {
                readUnlock();
                errorSaving("Write failed");
                throw errorPointer(new actionOnFileError(),os::shared_type);
            }
            --ntrc;
            --dtrc;
			--ttrc;
        }
        readUnlock();
        finishedSaving();
	}
    //Opens a key file
    void publicKey::loadFile()
    {
		writeLock();
        if(_fileName=="")
		{
			writeUnlock();
			throw errorPointer(new fileOpenError(),os::shared_type);
		}

        os::smart_ptr<binaryDecryptor> bde;
        if(_key==NULL || _keyLen==0)
			bde=os::smart_ptr<binaryDecryptor>(new binaryDecryptor(_fileName,"default"),os::shared_type);
        else
			bde=os::smart_ptr<binaryDecryptor>(new binaryDecryptor(_fileName,_key,_keyLen),os::shared_type);

        //Check if this is even a good file
        if(!bde->good())
		{
			writeUnlock();
			throw errorPointer(new actionOnFileError(),os::shared_type);
		}

        //Read in header
        unsigned char initArray[4];
        uint16_t dumpVal;
        bde->read(initArray,4);
        if(!bde->good())
		{
			writeUnlock();
			throw errorPointer(new actionOnFileError(),os::shared_type);
		}
        memcpy(&dumpVal,initArray,2);
        _size=os::from_comp_mode(dumpVal);
        memcpy(&dumpVal,initArray+2,2);
        if(algorithm()!=os::from_comp_mode(dumpVal))
		{
			writeUnlock();
			throw errorPointer(new illegalAlgorithmBind("RSA File Read"),os::shared_type);
		}

		//Read timestamp
		uint64_t tempts;
		bde->read((unsigned char*) &tempts,8);
		_timestamp=os::from_comp_mode(tempts);

        //Read keys
        os::smart_ptr<unsigned char>dumpArray(new unsigned char[2*4*_size],os::shared_type_array);
		os::smart_ptr<uint32_t>keyArray(new uint32_t[_size],os::shared_type_array);
        bde->read(dumpArray.get(),2*4*_size);
        if(!bde->good())
		{
			writeUnlock();
			throw errorPointer(new actionOnFileError(),os::shared_type);
		}

		//Parse keys
		for(unsigned int i1=0;i1<2;i1++)
		{
			memcpy(keyArray.get(),dumpArray.get()+i1*4*_size,4*_size);
			for(unsigned int i2=0;i2<_size;i2++)
			{
				keyArray.get()[i2]=os::from_comp_mode(keyArray.get()[i2]);
			}
			if(i1==0) n=copyConvert(keyArray.get(),_size);
			else d=copyConvert(keyArray.get(),_size);
		}

        //Old n and d's
        bde->read(initArray,2);
        if(!bde->good())
        {
            writeUnlock();
            throw errorPointer(new actionOnFileError(),os::shared_type);
        }
        memcpy(&dumpVal,initArray,2);
        _history=os::from_comp_mode(dumpVal);
        if(_history>20)
        {
            writeUnlock();
            throw errorPointer(new customError("History Size","History size invalid, must be less than or equal to 20"),os::shared_type);
        }

		//Read in old n and d, oldest first
		unsigned int numOlds=0;
		while(bde->bytesLeft()>0 && numOlds<_history)
		{
			bde->read((unsigned char*) &tempts,8);
			tempts=os::from_comp_mode(tempts);
			bde->read(dumpArray.get(),2*4*_size);
			if(!bde->good())
			{
				writeUnlock();
				throw errorPointer(new actionOnFileError(),os::shared_type);
			}

			//Parse timestamp
			_timestamps.insert(os::smart_ptr<uint64_t>(new uint64_t(tempts),os::shared_type));

			//Parse numbers
			for(unsigned int i1=0;i1<2;i1++)
			{
				memcpy(keyArray.get(),dumpArray.get()+i1*4*_size,4*_size);
				for(unsigned int i2=0;i2<_size;i2++)
				{
					keyArray.get()[i2]=os::from_comp_mode(keyArray.get()[i2]);
				}
				if(i1==0) oldN.insert(copyConvert(keyArray.get(),_size));
				else oldD.insert(copyConvert(keyArray.get(),_size));
			}
			numOlds++;
		}
		writeUnlock();
    }
    //Set the file name
	void publicKey::setFileName(std::string fileName)
    {
        _fileName=fileName;
        markChanged();
    }
	//Set password (by array)
	void publicKey::setPassword(unsigned char* key,size_t keyLen)
	{
        writeLock();
		if(_key) delete [] _key;
		_key=NULL;
		if(!key || keyLen==0)
        {
            writeUnlock();
            return;
        }

		_keyLen=keyLen;
		_key=new unsigned char[_keyLen];
		memcpy(_key,key,_keyLen);
        writeUnlock();

        markChanged();
	}
	//Set password (by string)
	void publicKey::setPassword(std::string password)
	{
		if(password=="") setPassword(NULL,0);
		else setPassword((unsigned char*)password.c_str(),password.length());
	}
	//Set algorithm to be used in encryption
	void publicKey::setEncryptionAlgorithm(os::smart_ptr<streamPackageFrame> stream_algo)
	{
		fePackage=stream_algo;
		markChanged();
	}

//Encoding and decoding---------------------------------------

    //Static encode (based on number)
    os::smart_ptr<number> publicKey::encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN, uint16_t size)
    {
        if(*code > *publicN)
            throw errorPointer(new publicKeySizeWrong(), os::shared_type);
        return code;
    }
    //Static hybrid encode
	void publicKey::encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN, uint16_t size)
	{
		os::smart_ptr<number> enc=publicKey::encode(publicKey::copyConvert(code,codeLength,size),publicN,size);
		size_t tLen;
		auto tdat=enc->getCompCharData(tLen);
		memset(code,0,codeLength);
		if(tLen>codeLength) memcpy(code,tdat.get(),codeLength);
		else memcpy(code,tdat.get(),tLen);
	}
	//Static raw encode
    void publicKey::encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength, uint16_t size)
    {
        os::smart_ptr<number> enc=publicKey::encode(publicKey::copyConvert(code,codeLength,size),publicKey::copyConvert(code,codeLength,size),size);
        size_t tLen;
		auto tdat=enc->getCompCharData(tLen);
		memset(code,0,codeLength);
		if(tLen>codeLength) memcpy(code,tdat.get(),codeLength);
		else memcpy(code,tdat.get(),tLen);
    }
	//Default encode
	os::smart_ptr<number> publicKey::encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN) const
	{
		if(!publicN) publicN=n;
        return publicKey::encode(code,publicN,size());
	}
	//Encode with raw data, public key
	void publicKey::encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN) const
	{publicKey::encode(code,codeLength,publicN,size());}
	//Encode with raw data
	void publicKey::encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength) const
    {publicKey::encode(code,codeLength,publicN,nLength,size());}

    //Default decode
	os::smart_ptr<number> publicKey::decode(os::smart_ptr<number> code) const
	{
		if(*code > *n) throw errorPointer(new publicKeySizeWrong(), os::shared_type);
		return code;
	}
	//Old decode
	os::smart_ptr<number> publicKey::decode(os::smart_ptr<number> code,size_t hist)
	{
		if(hist==CURRENT_INDEX) return decode(code);
		os::smart_ptr<number> histN=getOldN(hist);
		if(!histN) throw errorPointer(new NULLPublicKey(),os::shared_type);
		if(*code > *histN) throw errorPointer(new publicKeySizeWrong(), os::shared_type);
		return code;
	}
	//Decode with raw data
	void publicKey::decode(unsigned char* code, size_t codeLength) const
	{
		os::smart_ptr<number> enc=decode(copyConvert(code,codeLength));
		size_t tLen;
		auto tdat=enc->getCompCharData(tLen);
		memset(code,0,codeLength);
		if(tLen>codeLength) memcpy(code,tdat.get(),codeLength);
		else memcpy(code,tdat.get(),tLen);
	}
	//Old decode raw data
	void publicKey::decode(unsigned char* code, size_t codeLength,size_t hist)
	{
		os::smart_ptr<number> enc=decode(copyConvert(code,codeLength),hist);
		size_t tLen;
		auto tdat=enc->getCompCharData(tLen);
		memset(code,0,codeLength);
		if(tLen>codeLength) memcpy(code,tdat.get(),codeLength);
		else memcpy(code,tdat.get(),tLen);
	}

/*------------------------------------------------------------
    RSA Public Key
 ------------------------------------------------------------*/

    //Default constructor
    publicRSA::publicRSA(uint16_t sz):
        publicKey(algo::publicRSA,sz)
    {
        initE();
        generateNewKeys();
    }
    //Copy constructor
    publicRSA::publicRSA(publicRSA& ky):
        publicKey(ky)
    {
        initE();
        n=copyConvert(ky.n);
        d=copyConvert(ky.d);

        //Copy old n
        for(auto trc=ky.oldN.last();trc;--trc)
            oldN.insert(copyConvert(&trc));

        //Copy old d
        for(auto trc=ky.oldD.last();trc;--trc)
            oldD.insert(copyConvert(&trc));

		//Copy timestamps
        for(auto trc=ky._timestamps.last();trc;--trc)
			_timestamps.insert(&trc);

        markChanged();
    }
    //N, D constructor
    publicRSA::publicRSA(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d,uint16_t sz,uint64_t tms):
        publicKey(os::cast<number,integer>(_n),os::cast<number,integer>(_d),algo::publicRSA,sz,tms)
    {
        initE();
        n=copyConvert(os::cast<number,integer>(_n));
        d=copyConvert(os::cast<number,integer>(_d));
        markChanged();
    }
	//N and D from arrays
	publicRSA::publicRSA(uint32_t* _n,uint32_t* _d,uint16_t sz,uint64_t tms):
        publicKey(algo::publicRSA,sz)
	{
		initE();
		n=copyConvert(_n,sz);
        d=copyConvert(_d,sz);
		_timestamp=tms;
        markChanged();
	}
    //Load a public key from a file
    publicRSA::publicRSA(std::string fileName,std::string password,os::smart_ptr<streamPackageFrame> stream_algo):
        publicKey(algo::publicRSA,fileName,password,stream_algo)
    {
        initE();
        loadFile();
    }
    //Load a public key from a file
    publicRSA::publicRSA(std::string fileName,unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> stream_algo):
        publicKey(algo::publicRSA,fileName,key,keyLen,stream_algo)
    {
        initE();
        loadFile();
    }
    //Init the "e" variable
    void publicRSA::initE()
    {
        e=(integer::one()<<(unsigned)16)+integer::one();
    }

    //Static copy/convert
    os::smart_ptr<number> publicRSA::copyConvert(const os::smart_ptr<number> num,uint16_t size)
    {
        os::smart_ptr<number> ret(new integer(num->data(),num->size()),os::shared_type);
        ret->expand(size*2);
        return ret;
    }
    //Static copy/convert
    os::smart_ptr<number> publicRSA::copyConvert(const uint32_t* arr,size_t len,uint16_t size)
    {
        os::smart_ptr<number> ret;
		if(arr==NULL)
			ret=os::smart_ptr<number>(new integer(),os::shared_type);
		else
			ret=os::smart_ptr<number>(new integer(arr,(uint16_t)len),os::shared_type);
        ret->expand(size*2);
        return ret;
    }
    //Static copy/convert
    os::smart_ptr<number> publicRSA::copyConvert(const unsigned char* arr,size_t len,uint16_t size)
    {
        uint32_t* dumpArray=new uint32_t[len/4+1];
        memset(dumpArray,0,4*(len/4+1));
        memcpy(dumpArray,arr,len);
        for(unsigned int i=0;i<len/4+1;++i)
            dumpArray[i]=os::from_comp_mode(dumpArray[i]);
        os::smart_ptr<number> ret=publicRSA::copyConvert(dumpArray,len/4+1,size);
        delete [] dumpArray;
        return ret;
    }


    //Copy convert
    os::smart_ptr<number> publicRSA::copyConvert(const os::smart_ptr<number> num) const
    {return publicRSA::copyConvert(num,size());}
    //Copy convert
    os::smart_ptr<number> publicRSA::copyConvert(const uint32_t* arr,size_t len) const
    {return publicRSA::copyConvert(arr,len,size());}
    //Copy convert for raw byte array
    os::smart_ptr<number> publicRSA::copyConvert(const unsigned char* arr,size_t len) const
    {return publicRSA::copyConvert(arr,len,size());}

    //Static encode
    os::smart_ptr<number> publicRSA::encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN, uint16_t size)
    {
        if(*code > *publicN)
            throw errorPointer(new publicKeySizeWrong(), os::shared_type);
        if(code->typeID()!=numberType::Base10 || publicN->typeID()!=numberType::Base10)
            throw errorPointer(new illegalAlgorithmBind("Base10"),os::shared_type);
        integer e((integer::one()<<(unsigned)16)+integer::one());
        return os::smart_ptr<number> (new integer(os::cast<integer,number>(code)->moduloExponentiation(e, *os::cast<integer,number>(publicN))),os::shared_type);
	}
    //Static hybrid encode
	void publicRSA::encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN, uint16_t size)
	{
		os::smart_ptr<number> enc=publicRSA::encode(publicRSA::copyConvert(code,codeLength,size),publicN,size);
		size_t tLen;
		auto tdat=enc->getCompCharData(tLen);
		memset(code,0,codeLength);
		if(tLen>codeLength) memcpy(code,tdat.get(),codeLength);
		else memcpy(code,tdat.get(),tLen);
	}
	//Static raw encode
    void publicRSA::encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength, uint16_t size)
    {
        os::smart_ptr<number> enc=publicRSA::encode(publicRSA::copyConvert(code,codeLength,size),publicRSA::copyConvert(code,codeLength,size),size);
        size_t tLen;
		auto tdat=enc->getCompCharData(tLen);
		memset(code,0,codeLength);
		if(tLen>codeLength) memcpy(code,tdat.get(),codeLength);
		else memcpy(code,tdat.get(),tLen);
    }

    //Encode key
    os::smart_ptr<number> publicRSA::encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN) const
    {
        if(!publicN) publicN=n;
        return publicRSA::encode(code,publicN,size());
    }
    //Hybrid encode
	void publicRSA::encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN) const
	{
		if(!publicN) publicN=n;
		publicRSA::encode(code,codeLength,publicN,size());
	}
	//Raw encode
    void publicRSA::encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength) const
    {publicRSA::encode(code,codeLength,publicN,nLength,size());}

    //Decode key
    os::smart_ptr<number> publicRSA::decode(os::smart_ptr<number> code) const
    {
        if(code->typeID()!=numberType::Base10)
            throw errorPointer(new illegalAlgorithmBind("Base10"),os::shared_type);
        publicKey::decode(code);
        return os::smart_ptr<number>(new integer(os::cast<integer,number>(code)->moduloExponentiation(*os::cast<integer,number>(d), *os::cast<integer,number>(n))),os::shared_type);
    }
	//Old decode key
    os::smart_ptr<number> publicRSA::decode(os::smart_ptr<number> code, size_t hist)
    {
		if(hist==CURRENT_INDEX)
			return decode(code);
        if(code->typeID()!=numberType::Base10)
            throw errorPointer(new illegalAlgorithmBind("Base10"),os::shared_type);
        os::smart_ptr<number> histN=getOldN(hist);
		os::smart_ptr<number> histD=getOldD(hist);
		if(!histN) throw errorPointer(new NULLPublicKey(),os::shared_type);
		if(*code > *histN) throw errorPointer(new publicKeySizeWrong(), os::shared_type);

        return os::smart_ptr<number>(new integer(os::cast<integer,number>(code)->moduloExponentiation(*os::cast<integer,number>(histD), *os::cast<integer,number>(histN))),os::shared_type);
    }

/*------------------------------------------------------------
    RSA Public Key Generation
 ------------------------------------------------------------*/


	//Basic constructor
	RSAKeyGenerator::RSAKeyGenerator(publicRSA& m)
	{
		master=&m;
	}
	//Generate prime
	integer RSAKeyGenerator::generatePrime()
	{
		integer ret(2*master->size());
		for(uint16_t i=0;i<master->size()/2;++i)
			ret[i]=((uint32_t) rand())^(((uint32_t)rand())<<16);
		ret[0]=ret[0]|1;
		ret[master->size()/2-1]^=1<<31;
		while(!ret.prime())
			ret+=integer::two();
		return ret;
	}
	//Push calculated values
	void RSAKeyGenerator::pushValues()
	{
		master->writeLock();
		if(master->n && master->d) master->pushOldKeys(master->n,master->d,master->_timestamp);

		integer tn=p*q;
		integer phi = (p-integer::one())*(q-integer::one());
		phi.expand(2*master->size());
		integer td = master->e.modInverse(phi);

		master->n=os::smart_ptr<number>(new integer(tn),os::shared_type);
		master->d=os::smart_ptr<number>(new integer(td),os::shared_type);
		master->_timestamp=os::getTimestamp();
        master->n->expand(2*master->size());
		master->d->expand(2*master->size());

        publicRSA* temp=master;
        temp->keyGen=NULL;
		temp->writeUnlock();

		temp->readLock();
		temp->keyChangeSender::triggerEvent();
		temp->readUnlock();

        temp->markChanged();
	}

	//Key generation function
	namespace crypto
	{
		//Basic key generation thread
		void generateKeys(void* ptr)
		{
			RSAKeyGenerator* rkg=(RSAKeyGenerator*) ptr;
			rkg->p=rkg->generatePrime();
			rkg->q=rkg->generatePrime();
			rkg->pushValues();
		}
	}

	//Generating keys
	void publicRSA::generateNewKeys()
	{
		writeLock();

		if(keyGen)
		{
			writeUnlock();
			return;
		}

        srand((unsigned)time(NULL));
		keyGen=os::smart_ptr<RSAKeyGenerator>(new RSAKeyGenerator(*this),os::shared_type);
		os::spawnThread(&generateKeys,keyGen.get(),"RSA Key Generation");
		writeUnlock();
	}
    //Checks to see if we are even generating
    bool publicRSA::generating()
    {
		readLock();
        if(keyGen)
        {
            readUnlock();
            return true;
        }
		readUnlock();
        return false;
    }

#endif

///@endcond