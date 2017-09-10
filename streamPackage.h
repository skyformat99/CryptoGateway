/**

 * Declares a bank of stream ciphers and hash algorithms
 * along with  supporting classes.  Acts as a meta-object
 * construct for public-key algorithms.
 **/

#ifndef STREAM_PACKAGE_H
#define STREAM_PACKAGE_H

#include <string>
#include <stdint.h>
#include <vector>
#include "RC4_Hash.h"

namespace crypto {

    //Stream package frame
    class streamPackageFrame
    {
    protected:
        uint16_t _hashSize;
    public:
        streamPackageFrame(uint16_t hashSize=size::hash256){_hashSize=hashSize;}
        virtual ~streamPackageFrame(){}

        virtual os::smart_ptr<streamPackageFrame> getCopy() const {return NULL;}

		virtual hash hashEmpty() const {return xorHash();}
        virtual hash hashData(unsigned char* data, size_t len) const {return xorHash();}
        virtual hash hashCopy(unsigned char* data) const {return xorHash(data,_hashSize);}
        virtual os::smart_ptr<streamCipher> buildStream(unsigned char* data, size_t len) const {return NULL;}

		//Return stream type name
		virtual std::string streamAlgorithmName() const {return "NULL Stream";}
        virtual uint16_t streamAlgorithm() const {return algo::streamNULL;}

        //Return hash type name
        virtual std::string hashAlgorithmName() const {return "NULL hash";}
		virtual uint16_t hashAlgorithm() const {return algo::hashNULL;}

		void setHashSize(uint16_t hashSize) {_hashSize=hashSize;}
		uint16_t hashSize() const {return _hashSize;}
    };
    //Stream Encryption type
    template <class streamType, class hashType>
    class streamPackage: public streamPackageFrame
    {
    public:
        streamPackage(uint16_t hashSize=size::hash256):streamPackageFrame(hashSize){}
        virtual ~streamPackage(){}
        os::smart_ptr<streamPackageFrame> getCopy() const {return os::smart_ptr<streamPackageFrame>(new streamPackage<streamType,hashType>(_hashSize),os::shared_type);}

        //Preform the hash
		hash hashEmpty() const {return hashType();}
        hash hashData(unsigned char* data, size_t len) const
        {
            if(_hashSize==size::hash64)
                return hashType::hash64Bit(data,len);
            else if(_hashSize==size::hash128)
                return hashType::hash128Bit(data,len);
            else if(_hashSize==size::hash256)
                return hashType::hash256Bit(data,len);
            else if(_hashSize==size::hash512)
                return hashType::hash512Bit(data,len);
            return hashType::hash256Bit(data,len);
        }
        hash hashCopy(unsigned char* data) const {return rc4Hash(data,_hashSize);}

        //Build a stream
        os::smart_ptr<streamCipher> buildStream(unsigned char* data, size_t len) const
        {return os::smart_ptr<streamCipher>(new streamType(data,len),os::shared_type);}

        //Return stream type name
        std::string streamAlgorithmName() const {return streamType::staticAlgorithmName();}
        uint16_t streamAlgorithm() const {return streamType::staticAlgorithm();}

        //Return hash type name
        std::string hashAlgorithmName() const {return hashType::staticAlgorithmName();}
        uint16_t hashAlgorithm() const {return hashType::staticAlgorithm();}
    };

    //Encryption stream type bank
    class streamPackageTypeBank
    {
		os::smart_ptr<streamPackageFrame> _defaultPackage;
        std::vector<os::smart_ptr<std::vector<os::smart_ptr<streamPackageFrame> > > > packageVector;

        streamPackageTypeBank();
    public:
        virtual ~streamPackageTypeBank(){}
        static os::smart_ptr<streamPackageTypeBank> singleton();

        void setDefaultPackage(os::smart_ptr<streamPackageFrame> package);
		const os::smart_ptr<streamPackageFrame> defaultPackage() const {return _defaultPackage;}
        void pushPackage(os::smart_ptr<streamPackageFrame> package);
        const os::smart_ptr<streamPackageFrame> findStream(uint16_t streamID,uint16_t hashID) const;
		const os::smart_ptr<streamPackageFrame> findStream(const std::string& streamName,const std::string& hashName) const;
    };
}

#endif
