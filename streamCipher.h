/**
 * Defines some basic stream ciphers and stream
 * cipher tools for basic encryption.
 **/

#ifndef STREAM_CIPHER_H
#define STREAM_CIPHER_H

#include "Datastructures/Datastructures.h"
#include "cryptoConstants.h"
#include "cryptoNumber.h"

#include <stdint.h>

extern bool global_logging;

namespace crypto {

	//Entirely virtual class
	class streamCipher
	{
	public:
		virtual ~streamCipher(){}
		virtual uint8_t getNext() {return 0;}

        inline static uint16_t staticAlgorithm() {return algo::streamNULL;}
        inline static std::string staticAlgorithmName() {return "NULL Algorithm";}

        inline virtual uint16_t algorithm() const {return streamCipher::staticAlgorithm();}
		inline virtual const std::string algorithmName() const {return streamCipher::staticAlgorithmName();}
	};

	//RC Four
	class RCFour: public streamCipher
	{
	private:
		uint8_t* SArray;
		int i;
		int j;
		int u;

	public:
		//Constructor
		RCFour(uint8_t* arr, size_t len);
		virtual ~RCFour();

		uint8_t getNext();

        inline static uint16_t staticAlgorithm() {return algo::streamRC4;}
        inline static std::string staticAlgorithmName() {return "RC-4";}

        inline uint16_t algorithm() const {return RCFour::staticAlgorithm();}
		inline const std::string algorithmName() const {return RCFour::staticAlgorithmName();;}
	};

    //Stream packet
    class streamPacket
    {
    private:
        uint8_t* packetArray;
        uint16_t identifier;
        unsigned int size;

    public:
        streamPacket(os::smart_ptr<streamCipher> source, unsigned int s);
        virtual ~streamPacket();

        uint16_t getIdentifier() const;
        const uint8_t* getPacket() const;
        uint8_t* encrypt(uint8_t* pt, size_t len, bool surpress=true) const;
    };

	//Encrypts a byte stream
	class streamEncrypter
	{
	private:
		os::smart_ptr<streamCipher> cipher;
		unsigned int last_loc;
		uint16_t* ID_check;

	public:
		streamEncrypter(os::smart_ptr<streamCipher> c);
		virtual ~streamEncrypter();

		uint8_t* sendData(uint8_t* array, size_t len, uint16_t& flag);
	};

	//Decrypts a byte stream
	class streamDecrypter
	{
	private:
		os::smart_ptr<streamCipher> cipher;
		streamPacket** packetArray;
		unsigned int last_value;
		unsigned int mid_value;

	public:
		streamDecrypter(os::smart_ptr<streamCipher> c);
		virtual ~streamDecrypter();

		uint8_t* recieveData(uint8_t* array, size_t len, uint16_t flag);
	};
};

#endif
