/**
 * Implements the binary encryption files.
 * Consult binaryEncryption.h for details
 * on using these classes.
 **/

 ///@cond INTERNAL
#ifndef BINARY_ENCRYPTION_CPP
#define BINARY_ENCRYPTION_CPP

#include <string>
#include <stdint.h>
#include "binaryEncryption.h"
#include "keyBank.h"

namespace crypto {

/*------------------------------------------------------------
     Binary Encryption
 ------------------------------------------------------------*/

	//Construct with public key
	binaryEncryptor::binaryEncryptor(std::string file_name,os::smart_ptr<publicKey> publicKeyLock,unsigned int lockType,os::smart_ptr<streamPackageFrame> stream_algo):
		output(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_streamAlgorithm=stream_algo;
		_publicLockType=lockType;
		if(!stream_algo) _streamAlgorithm=streamPackageTypeBank::singleton()->defaultPackage();
		if(!publicKeyLock)
		{
			logError(errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type));
			output.close();
			_state=false;
		}
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			output.close();
			_state=false;
		}
		if(_publicLockType==file::PRIVATE_UNLOCK)
			build(publicKeyLock->getN(),publicKeyLock->algorithm(),publicKeyLock->size());
		else
			build(publicKeyLock);
	}
	binaryEncryptor::binaryEncryptor(std::string file_name,os::smart_ptr<number> publicKey,unsigned int pkAlgo,size_t pkSize,os::smart_ptr<streamPackageFrame> stream_algo)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_streamAlgorithm=stream_algo;
		_publicLockType=file::PRIVATE_UNLOCK;
		if(!stream_algo) _streamAlgorithm=streamPackageTypeBank::singleton()->defaultPackage();
		if(!publicKey || pkAlgo!=algo::publicNULL)
		{
			logError(errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type));
			output.close();
			_state=false;
		}
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			output.close();
			_state=false;
		}
		build(publicKey,pkAlgo,pkSize);
	}
	//Constructor with password
	binaryEncryptor::binaryEncryptor(std::string file_name,std::string password,os::smart_ptr<streamPackageFrame> stream_algo):
		output(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_streamAlgorithm=stream_algo;
		if(!stream_algo) _streamAlgorithm=streamPackageTypeBank::singleton()->defaultPackage();
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			output.close();
			_state=false;
		}
		else build((unsigned char*)password.c_str(),password.length());
	}
	//Constructor with raw array
	binaryEncryptor::binaryEncryptor(std::string file_name,unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> stream_algo):
		output(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_streamAlgorithm=stream_algo;
		if(!stream_algo) _streamAlgorithm=streamPackageTypeBank::singleton()->defaultPackage();
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError(),os::shared_type));
			output.close();
			_state=false;
		}
		else build(key,keyLen);
	}
	//Build (triggered by encryptor)
	void binaryEncryptor::build(unsigned char* key,size_t keyLen)
	{
		try
		{
			//Check key size first
			if(keyLen<1) throw errorPointer(new passwordSmallError(),os::shared_type);
			if(!_streamAlgorithm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);

			//Attempt to output header
			uint16_t valHld;
			unsigned char head[10];
			//Public key
			valHld=os::to_comp_mode(algo::publicNULL);
			memcpy(head,&valHld,2);
			valHld=os::to_comp_mode(algo::publicNULL);
			memcpy(head+2,&valHld,2);

			//Stream
			valHld=os::to_comp_mode(_streamAlgorithm->streamAlgorithm());
			memcpy(head+4,&valHld,2);

			//Hash
			valHld=os::to_comp_mode(_streamAlgorithm->hashAlgorithm());
			memcpy(head+6,&valHld,2);
			valHld=os::to_comp_mode(_streamAlgorithm->hashSize());
			memcpy(head+8,&valHld,2);
			output.write((char*)head,10);
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Hash password and write it to file
			hash hsh=_streamAlgorithm->hashData(key,keyLen);
			output.write((char*)hsh.data(),hsh.size());
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Generate stream cipher
			currentCipher=_streamAlgorithm->buildStream(key,keyLen);
			if(!currentCipher) throw errorPointer(new illegalAlgorithmBind("NULL build stream"),os::shared_type);
		}
		catch(errorPointer ptr)
		{
			logError(ptr);
			output.close();
			_state=false;
		}
	}
	//Build (triggered by public key encryptor
	void binaryEncryptor::build(os::smart_ptr<publicKey> publicKeyLock)
	{
		publicKeyLock->readLock();
		try
		{
			//Check key size first
			if(!publicKeyLock) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			if(!_streamAlgorithm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);

			//Attempt to output header
			uint16_t valHld;
			unsigned char head[11];
			//Public key
			valHld=os::to_comp_mode(publicKeyLock->algorithm());
			memcpy(head,&valHld,2);
			valHld=os::to_comp_mode(publicKeyLock->size());
			memcpy(head+2,&valHld,2);

			//Stream
			valHld=os::to_comp_mode(_streamAlgorithm->streamAlgorithm());
			memcpy(head+4,&valHld,2);

			//Hash
			valHld=os::to_comp_mode(_streamAlgorithm->hashAlgorithm());
			memcpy(head+6,&valHld,2);
			valHld=os::to_comp_mode(_streamAlgorithm->hashSize());
			memcpy(head+8,&valHld,2);

			//Lock type
			head[10]=_publicLockType;

			output.write((char*)head,11);
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Output hash of public key
			size_t arrSize;
			os::smart_ptr<unsigned char> randkey=publicKeyLock->getN()->getCompCharData(arrSize);
			hash hsh=_streamAlgorithm->hashData(randkey.get(),arrSize);
			//Output public key if encrypting with private key
			if(_publicLockType==file::PUBLIC_UNLOCK)
				output.write((char*)randkey.get(),arrSize);
			//Else, output a hash of the public key
			else
				output.write((char*)hsh.data(),hsh.size());

			//Generate key, and hash
			srand((unsigned)time(NULL));
			unsigned int arrayLen=publicKeyLock->size()*4;
			if(_publicLockType==file::DOUBLE_LOCK) arrayLen=publicKeyLock->size()*8;
			randkey=os::smart_ptr<unsigned char>(new unsigned char[arrayLen],os::shared_type_array);

			memset(randkey.get(),0,arrayLen);
			for(uint16_t i=0;i<(publicKeyLock->size()-1)*4;++i)
				randkey[i]=rand();
			if(_publicLockType==file::DOUBLE_LOCK)
			{
				for(uint16_t i=0;i<(publicKeyLock->size()-1)*4;++i)
					randkey[i+publicKeyLock->size()*4]=rand();
			}
			hsh=_streamAlgorithm->hashData(randkey.get(),arrayLen);

			//Generate stream cipher
			currentCipher=_streamAlgorithm->buildStream(randkey.get(),arrayLen);
			if(!currentCipher) throw errorPointer(new illegalAlgorithmBind("NULL build stream"),os::shared_type);

			//Encrypt with private key
			if(_publicLockType==file::PUBLIC_UNLOCK)
				publicKeyLock->decode(randkey.get(),publicKeyLock->size()*4);
			//Encrypt with private then public
			else if(_publicLockType==file::DOUBLE_LOCK)
			{
				publicKeyLock->decode(randkey.get(),publicKeyLock->size()*4);
				publicKeyLock->encode(randkey.get()+publicKeyLock->size()*4,publicKeyLock->size()*4);
			}
			//Default case, encrypt with public key
			else
				publicKeyLock->encode(randkey.get(),publicKeyLock->size()*4);
			output.write((char*)randkey.get(),arrayLen);
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Hash output
			output.write((char*)hsh.data(),hsh.size());
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);
		}
		catch(errorPointer ptr)
		{
			logError(ptr);
			output.close();
			_state=false;
		}
		publicKeyLock->readUnlock();
	}
	//Build (public key encryption)
	void binaryEncryptor::build(os::smart_ptr<number> pubKey,unsigned int pkAlgo,size_t pkSize)
	{
		try
		{
			//Check key size first
			if(!pubKey) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			if(!_streamAlgorithm) throw errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type);
			os::smart_ptr<publicKeyPackageFrame> pkframe=publicKeyTypeBank::singleton()->findPublicKey(pkAlgo);
			if(!pkframe) throw errorPointer(new illegalAlgorithmBind("Public key algorithm: "+std::to_string((long long unsigned int)pkAlgo)),os::shared_type);
			pkframe=pkframe->getCopy();
			pkframe->setKeySize((uint16_t)pkSize);

			//Attempt to output header
			uint16_t valHld;
			unsigned char head[11];
			//Public key
			valHld=os::to_comp_mode(pkframe->algorithm());
			memcpy(head,&valHld,2);
			valHld=os::to_comp_mode(pkframe->keySize());
			memcpy(head+2,&valHld,2);

			//Stream
			valHld=os::to_comp_mode(_streamAlgorithm->streamAlgorithm());
			memcpy(head+4,&valHld,2);

			//Hash
			valHld=os::to_comp_mode(_streamAlgorithm->hashAlgorithm());
			memcpy(head+6,&valHld,2);
			valHld=os::to_comp_mode(_streamAlgorithm->hashSize());
			memcpy(head+8,&valHld,2);

			//Lock type
			head[10]=_publicLockType;

			output.write((char*)head,11);
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Output hash of public key
			size_t arrSize;
			os::smart_ptr<unsigned char> randkey=pubKey->getCompCharData(arrSize);
			hash hsh=_streamAlgorithm->hashData(randkey.get(),arrSize);
			output.write((char*)hsh.data(),hsh.size());

			//Generate key, and hash
			srand((unsigned)time(NULL));
			randkey=os::smart_ptr<unsigned char>(new unsigned char[pkframe->keySize()*4],os::shared_type_array);
			memset(randkey.get(),0,pkframe->keySize()*4);
			for(uint16_t i=0;i<(pkframe->keySize()-1)*4;++i)
				randkey[i]=rand();
			hsh=_streamAlgorithm->hashData(randkey.get(),pkframe->keySize()*4);

			//Generate stream cipher
			currentCipher=_streamAlgorithm->buildStream(randkey.get(),pkframe->keySize()*4);
			if(!currentCipher) throw errorPointer(new illegalAlgorithmBind("NULL build stream"),os::shared_type);

			//Encrypt random key with public key
			pkframe->encode(randkey.get(),pkframe->keySize()*4,pubKey);
			output.write((char*)randkey.get(),pkframe->keySize()*4);
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Hash output
			output.write((char*)hsh.data(),hsh.size());
			if(!output.good()) throw errorPointer(new fileOpenError(),os::shared_type);
		}
		catch(errorPointer ptr)
		{
			logError(ptr);
			output.close();
			_state=false;
		}
	}

	//Write data
	void binaryEncryptor::write(unsigned char data)
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		output.put(data^currentCipher->getNext());
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError(),os::shared_type));
			output.close();
			_state=false;
		}
	}
	//Write data
	void binaryEncryptor::write(const unsigned char* data,size_t dataLen)
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		unsigned char* arr=new unsigned char[dataLen];
		for(unsigned int i=0;i<dataLen;++i)
			arr[i]=data[i]^currentCipher->getNext();
		output.write((char*)arr,dataLen);
		delete [] arr;
		if(!output.good())
		{
			logError(errorPointer(new fileOpenError(),os::shared_type));
			output.close();
			_state=false;
		}
	}
	//Close current binary file encryptor
	void binaryEncryptor::close()
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		_finished=true;
		currentCipher=NULL;
		output.close();
	}

/*------------------------------------------------------------
     Binary Decryption
 ------------------------------------------------------------*/

	//Binary decryptor, with public key
	binaryDecryptor::binaryDecryptor(std::string file_name,os::smart_ptr<publicKey> publicKeyLock):
		input(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_bytesLeft=0;
		_publicKeyLock=publicKeyLock;
		if(!_publicKeyLock)
		{
			logError(errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type));
			input.close();
			_state=false;
		}
		if(!input.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			input.close();
			_state=false;
		}
		else build();
	}
	//Binary decryptor, with key bank
	binaryDecryptor::binaryDecryptor(std::string file_name,os::smart_ptr<keyBank> kBank):
		input(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_bytesLeft=0;
		_keyBank=kBank;
		if(!_keyBank)
		{
			logError(errorPointer(new illegalAlgorithmBind("NULL Stream"),os::shared_type));
			input.close();
			_state=false;
		}
		if(!input.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			input.close();
			_state=false;
		}
		else build();
	}
	//Binary decryptor string password constructor
	binaryDecryptor::binaryDecryptor(std::string file_name,std::string password):
		input(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_bytesLeft=0;
		if(!input.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			input.close();
			_state=false;
		}
		else build((unsigned char*)password.c_str(),password.length());
	}
	//Binary decryptor byte array constructor
	binaryDecryptor::binaryDecryptor(std::string file_name,unsigned char* key,size_t keyLen):
		input(file_name,std::ios::binary)
	{
		_fileName=file_name;
		_state=true;
		_finished=false;
		_bytesLeft=0;
		if(!input.good())
		{
			logError(errorPointer(new fileOpenError,os::shared_type));
			input.close();
			_state=false;
		}
		else build(key,keyLen);
	}
	//Builds the file for decryption (with error logging)
	void binaryDecryptor::build(unsigned char* key,size_t keyLen)
	{
		if(_publicKeyLock) _publicKeyLock->readLock();
		try
		{
			//Bind file length
			std::streampos fsize;
			fsize = input.tellg();
			input.seekg( 0, std::ios::end );
			_bytesLeft = (unsigned long) (input.tellg() - fsize);
			input.seekg (0, std::ios::beg);

			//Data values
			uint16_t publicAlgoVal;
			uint16_t publicSizeVal;
			uint16_t streamAlgoVal;
			uint16_t hashAlgoVal;
			uint16_t hashSizeVal;
			unsigned int pkType;

			//Read data
			unsigned char buffer[2048];
			input.read((char*)buffer,10);
			_bytesLeft-=10;
			memcpy(&publicAlgoVal,buffer,2);
			memcpy(&publicSizeVal,buffer+2,2);
			memcpy(&streamAlgoVal,buffer+4,2);
			memcpy(&hashAlgoVal,buffer+6,2);
			memcpy(&hashSizeVal,buffer+8,2);

			publicAlgoVal=os::from_comp_mode(publicAlgoVal);
			publicSizeVal=os::from_comp_mode(publicSizeVal);
			streamAlgoVal=os::from_comp_mode(streamAlgoVal);
			hashAlgoVal=os::from_comp_mode(hashAlgoVal);
			hashSizeVal=os::from_comp_mode(hashSizeVal);

			//Check if input is good
			if(!input.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Read PK type (if applicable)
			if(publicAlgoVal!=algo::publicNULL)
			{
				input.read((char*)buffer,1);
				_bytesLeft-=1;
				pkType=buffer[0];
			}
			if(!input.good()) throw errorPointer(new fileOpenError(),os::shared_type);

			//Bind algorithm
			_streamAlgorithm=streamPackageTypeBank::singleton()->findStream(streamAlgoVal,hashAlgoVal);
			if(!_streamAlgorithm) throw errorPointer(new illegalAlgorithmBind("Stream ID: "+std::to_string((long long unsigned int)streamAlgoVal)+", Hash ID: "+std::to_string((long long unsigned int)hashAlgoVal)),os::shared_type);
			_streamAlgorithm=_streamAlgorithm->getCopy();
			_streamAlgorithm->setHashSize(hashSizeVal);

			//Check key size first
			hash calcHash=_streamAlgorithm->hashEmpty();
			if(publicAlgoVal==algo::publicNULL)
			{
				if(key==NULL||keyLen<1) throw errorPointer(new passwordSmallError(),os::shared_type);
				calcHash=_streamAlgorithm->hashData(key,keyLen);
				currentCipher=_streamAlgorithm->buildStream(key,keyLen);
			}
			else
			{
				//Read hash case (private and double unlock)
				if(pkType==file::PRIVATE_UNLOCK || pkType==file::DOUBLE_LOCK)
				{
					if(!_publicKeyLock) throw errorPointer(new illegalAlgorithmBind("NULL Public Key"),os::shared_type);
					if(_publicKeyLock->algorithm()!=publicAlgoVal) throw errorPointer(new illegalAlgorithmBind("Algorithm ID mismatch"),os::shared_type);
					if(_publicKeyLock->size()!=publicSizeVal) throw errorPointer(new illegalAlgorithmBind("Algorithm size mismatch"),os::shared_type);

					//Read hash
					input.read((char*)buffer,_streamAlgorithm->hashSize());
					_bytesLeft-=_streamAlgorithm->hashSize();
					hash keyHash=_streamAlgorithm->hashCopy(buffer);

					size_t kIndex;
					bool kType;
					if(!_publicKeyLock->searchKey(keyHash,kIndex,kType))
						throw errorPointer(new keyMissing(),os::shared_type);

					//Read key into buffer
					unsigned int keyLen=_publicKeyLock->size()*4;
					if(pkType==file::DOUBLE_LOCK)
						keyLen=keyLen*2;
					input.read((char*)buffer,keyLen);
					_bytesLeft-=keyLen;
					if(pkType==file::PRIVATE_UNLOCK)
						_publicKeyLock->decode(buffer,_publicKeyLock->size()*4,kIndex);
					else
					{
						_publicKeyLock->encode(buffer,_publicKeyLock->size()*4,_publicKeyLock->getOldN(kIndex));
						_publicKeyLock->decode(buffer+_publicKeyLock->size()*4,_publicKeyLock->size()*4,kIndex);
					}
					calcHash=_streamAlgorithm->hashData(buffer,keyLen);
					currentCipher=_streamAlgorithm->buildStream(buffer,keyLen);
				}
				//Public key case (read key)
				else
				{
					if(!_publicKeyLock && !_keyBank) throw errorPointer(new illegalAlgorithmBind("No key check available"),os::shared_type);
					input.read((char*)buffer,publicSizeVal*4);
					_bytesLeft-=publicSizeVal*4;

					os::smart_ptr<publicKeyPackageFrame> pkframe=publicKeyTypeBank::singleton()->findPublicKey(publicAlgoVal);
					if(!pkframe) throw errorPointer(new illegalAlgorithmBind("Public key algorithm: "+std::to_string((long long unsigned int)publicAlgoVal)),os::shared_type);
					pkframe=pkframe->getCopy();
					pkframe->setKeySize(publicSizeVal);
					os::smart_ptr<number> tempNum=pkframe->convert(buffer,publicSizeVal*4);

					//Check keys
					size_t dmp1;
					bool dmp2;
					if(_publicKeyLock)
					{
						if(!_publicKeyLock->searchKey(tempNum,dmp1,dmp2))
							throw errorPointer(new keyMissing(),os::shared_type);
					}
					else
					{
						_author=_keyBank->find(tempNum,publicAlgoVal,publicSizeVal);
						if(!_author)
							throw errorPointer(new keyMissing(),os::shared_type);
					}

					//Read key into buffer
					input.read((char*)buffer,publicSizeVal*4);
					_bytesLeft-=publicSizeVal*4;
					pkframe->encode(buffer,publicSizeVal*4,tempNum);
					calcHash=_streamAlgorithm->hashData(buffer,publicSizeVal*4);
					currentCipher=_streamAlgorithm->buildStream(buffer,publicSizeVal*4);
				}
			}

			//Pull hash
			input.read((char*)buffer,calcHash.size());
			_bytesLeft-=calcHash.size();
			if(!input.good()) throw errorPointer(new fileOpenError(),os::shared_type);
			hash pullHash=_streamAlgorithm->hashCopy(buffer);

			//Check hash
			if(calcHash!=pullHash) throw errorPointer(new hashCompareError(),os::shared_type);
		}
		catch(errorPointer ptr)
		{
			logError(ptr);
			input.close();
			_state=false;
			_bytesLeft=0;
			currentCipher=NULL;
		}
		if(_publicKeyLock) _publicKeyLock->readUnlock();
	}

	//Read character
	unsigned char binaryDecryptor::read()
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return 0;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return 0;
		}
		unsigned char ret=input.get()^currentCipher->getNext();
		_bytesLeft--;
		if(_bytesLeft<=0||!input.good())
		{
			_bytesLeft=0;
			if(!input.good())
			{
				logError(errorPointer(new fileOpenError(),os::shared_type));
				_state=false;
			}
			else _finished=true;
			input.close();
		}
		return ret;
	}
	//Read byte array
	size_t binaryDecryptor::read(unsigned char* data,size_t dataLen)
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return 0;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return 0;
		}
		size_t readTarg=dataLen;
		if(readTarg>_bytesLeft) readTarg=_bytesLeft;
		input.read((char*) data,dataLen);

		//Decrypt data
		for(unsigned int i=0;i<readTarg;++i)
			data[i]=data[i]^currentCipher->getNext();
		_bytesLeft-=readTarg;
		if(_bytesLeft<=0||!input.good())
		{
			_bytesLeft=0;
			if(!input.good())
			{
				logError(errorPointer(new fileOpenError(),os::shared_type));
				_state=false;
			}
			else _finished=true;
			input.close();
		}
		return readTarg;
	}
	//Close binary decryptor
	void binaryDecryptor::close()
	{
		if(!_state)
		{
			logError(errorPointer(new actionOnFileError(),os::shared_type));
			return;
		}
		if(_finished)
		{
			logError(errorPointer(new actionOnFileClosed(),os::shared_type));
			return;
		}
		_finished=true;
		currentCipher=NULL;
		input.close();
		_bytesLeft=0;
	}
//Simple Access Functions

	os::smart_ptr<nodeGroup> binaryDecryptor::author() {return _author;}
	//Special case, GCC wants this in a .cpp file
	binaryDecryptor::~binaryDecryptor(){close();}
}

#endif
///@endcond