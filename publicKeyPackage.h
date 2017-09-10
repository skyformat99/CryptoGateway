/**
 * Declares a bank of public keys as well as
 * supporting classes.  Acts as a meta-object
 * construct for public-key algorithms.
 **/

#ifndef PUBLIC_KEY_PACKAGE_H
#define PUBLIC_KEY_PACKAGE_H

#include "cryptoPublicKey.h"

namespace crypto {
    //Public key package frame
    class publicKeyPackageFrame
    {
    protected:
        uint16_t _publicSize;
    public:
        publicKeyPackageFrame(uint16_t publicSize=size::public512){_publicSize=publicSize;}
        virtual ~publicKeyPackageFrame(){}

        virtual os::smart_ptr<publicKeyPackageFrame> getCopy() const {return NULL;}

		virtual os::smart_ptr<number> convert(uint32_t* arr, size_t len) const{return publicKey::copyConvert(arr,len,_publicSize);}
        virtual os::smart_ptr<number> convert(const unsigned char* arr,size_t len) const{return publicKey::copyConvert(arr,len,_publicSize);}

        virtual os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN) const
        {return publicKey::encode(code,publicN,_publicSize);}
		virtual void encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN) const
		{publicKey::encode(code,codeLength,publicN,_publicSize);}
        virtual void encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength) const
        {publicKey::encode(code,codeLength,publicN,nLength,_publicSize);}


        virtual os::smart_ptr<publicKey> generate() const {return NULL;}
        virtual os::smart_ptr<publicKey> bindKeys(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d) const {return NULL;}
        virtual os::smart_ptr<publicKey> bindKeys(uint32_t* _n,uint32_t* _d) const {return NULL;}

        virtual os::smart_ptr<publicKey> openFile(std::string fileName,std::string password) const {return NULL;}
        virtual os::smart_ptr<publicKey> openFile(std::string fileName,unsigned char* key,size_t keyLen) const {return NULL;}

        //Return data info
        virtual std::string algorithmName() const {return "NULL public key";}
        virtual uint16_t algorithm() const {return algo::publicNULL;}

        void setKeySize(uint16_t publicSize) {_publicSize=publicSize;}
        uint16_t keySize() const {return _publicSize;}
    };
    //Stream Encryption type
    template <class pkType>
    class publicKeyPackage: public publicKeyPackageFrame
	{
	public:
		publicKeyPackage(uint16_t publicSize=size::public512):publicKeyPackageFrame(publicSize){}
        virtual ~publicKeyPackage(){}
        os::smart_ptr<publicKeyPackageFrame> getCopy() const {return os::smart_ptr<publicKeyPackageFrame>(new publicKeyPackage<pkType>(_publicSize),os::shared_type);}

		os::smart_ptr<number> convert(uint32_t* arr, size_t len) const{return pkType::copyConvert(arr,len,_publicSize);}
        os::smart_ptr<number> convert(const unsigned char* arr,size_t len) const{return pkType::copyConvert(arr,len,_publicSize);}

        os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN) const
        {return pkType::encode(code,publicN,_publicSize);}
		void encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN) const
		{pkType::encode(code,codeLength,publicN,_publicSize);}
        void encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength) const
        {pkType::encode(code,codeLength,publicN,nLength,_publicSize);}

		os::smart_ptr<publicKey> generate() const {return os::smart_ptr<publicKey>(new pkType(_publicSize),os::shared_type);}
        os::smart_ptr<publicKey> bindKeys(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d) const {return os::smart_ptr<publicKey>(new pkType(_n,_d,_publicSize),os::shared_type);}
        os::smart_ptr<publicKey> bindKeys(uint32_t* _n,uint32_t* _d) const {return os::smart_ptr<publicKey>(new pkType(_n,_d,_publicSize),os::shared_type);}
        os::smart_ptr<publicKey> openFile(std::string fileName,std::string password) const {return os::smart_ptr<publicKey>(new pkType(fileName,password),os::shared_type);}
        os::smart_ptr<publicKey> openFile(std::string fileName,unsigned char* key,size_t keyLen) const {return os::smart_ptr<publicKey>(new pkType(fileName,key,keyLen),os::shared_type);}

		//Return data info
        std::string algorithmName() const {return pkType::staticAlgorithmName();}
        uint16_t algorithm() const {return pkType::staticAlgorithm();}
	};
    //Public key type bank
    class publicKeyTypeBank
    {
        os::smart_ptr<publicKeyPackageFrame> _defaultPackage;
        std::vector<os::smart_ptr<publicKeyPackageFrame> > packageVector;

        publicKeyTypeBank();
    public:
        virtual ~publicKeyTypeBank(){}
        static os::smart_ptr<publicKeyTypeBank> singleton();

        void setDefaultPackage(os::smart_ptr<publicKeyPackageFrame> package);
        const os::smart_ptr<publicKeyPackageFrame> defaultPackage() const {return _defaultPackage;}
        void pushPackage(os::smart_ptr<publicKeyPackageFrame> package);
        const os::smart_ptr<publicKeyPackageFrame> findPublicKey(uint16_t pkID) const;
        const os::smart_ptr<publicKeyPackageFrame> findPublicKey(const std::string& pkName) const;
    };
}

#endif
