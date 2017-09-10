/**
 * Implements the RC-4 stream cipher and
 * more generally, a framework for all stream
 * ciphers to use.
 **/

 ///@cond INTERNAL

#ifndef STREAM_CIPHER_CPP
#define STREAM_CIPHER_CPP

#include "cryptoConstants.h"
#include "cryptoLogging.h"
#include "streamCipher.h"
#include "cryptoError.h"

#include <string>
#include <iostream>
#include <stdlib.h>

using namespace std;
using namespace crypto;

//Code Packet-----------------------------------------------------------------

	//Constructor
	streamPacket::streamPacket(os::smart_ptr<streamCipher> source, unsigned int s)
	{
		//Check streamCipher
		if(source==NULL||source->algorithm()==algo::streamNULL)
		{
			if(source!=NULL) throw errorPointer(new illegalAlgorithmBind(source->algorithmName()),os::shared_type);
			else throw errorPointer(new illegalAlgorithmBind("NULL Pointer"),os::shared_type);
		}

		if(s>20) size = s;
		else throw errorPointer(new bufferSmallError(),os::shared_type);

		//Initialize the packet Array
		unsigned cnt = 0;
		packetArray = new uint8_t[size];
		packetArray[0] = source->getNext();
		packetArray[1] = source->getNext();

		identifier = (((uint16_t) packetArray[0])<<8) ^ packetArray[1];

		while(cnt<size)
		{
		  packetArray[cnt] = source->getNext();
		  ++cnt;
		}
	}
	//Destructor
	streamPacket::~streamPacket(){delete(packetArray);}
	//Returns the identifier
	uint16_t streamPacket::getIdentifier() const {return identifier;}
	//Returns the packet data
	const uint8_t* streamPacket::getPacket() const{return packetArray;}
	//Encrypts, dynamic suppression
	uint8_t* streamPacket::encrypt(uint8_t* pt, size_t len, bool surpress) const
	{
		if(!surpress && len>size)
			throw errorPointer(new customError("Unsecure length","The length of your input to codePacket.encrypt(...) is unsecure!"),os::shared_type);
		unsigned int cnt = 0;
		while(cnt<len)
		{
			pt[cnt] = pt[cnt] ^ packetArray[cnt%size];
			++cnt;
		}

		return pt;
	}

	//Constructor
	RCFour::RCFour(uint8_t* arr, size_t len)
	{
		//Check the array length
		if(len<1) throw errorPointer(new passwordSmallError(),os::shared_type);
		if(size::RC4_MAX<len || size::STREAM_SEED_MAX<len) throw errorPointer(new passwordLargeError(),os::shared_type);

		//Initialize the S array
		SArray  = new uint8_t [size::RC4_MAX];

		i = 0;
		while(i<size::RC4_MAX)
		{
			SArray[i] = i;
			++i;
		}

		//Set the initial permutaion
		i = 0;
		j = 0;

		while(i<size::RC4_MAX)
		{
			j=(j+SArray[i]+arr[i%len])%size::RC4_MAX;
			u = SArray[i];
			SArray[i] = SArray[j];
			SArray[j] = u;
			++i;
		}

		i = 0;
		j = 0;
		u = 0;
	}
	//Destructor
	RCFour::~RCFour(){delete(SArray);}
	//Return the next element the stream generates
	uint8_t RCFour::getNext()
	{
		int temp;

		u++;
		i = (i+1)%size::RC4_MAX;
		j = (j+ SArray[i])%size::RC4_MAX;

		temp = SArray[i];
		SArray[i] = SArray[j];
		SArray[j] = temp;
		return ((uint8_t) (SArray[(SArray[i]+SArray[j])%size::RC4_MAX]));
	}

//Stream Encrypter---------------------------------------------------------------------------

	//Constructor
	streamEncrypter::streamEncrypter(os::smart_ptr<streamCipher> c)
	{
		cipher = c;
		last_loc = 0;
		ID_check=new uint16_t[size::stream::BACKCHECK];

		//Set ID array to 0
		int cnt = 0;
		while(cnt<size::stream::BACKCHECK)
		{
		  ID_check[cnt] = 0;
		  ++cnt;
		}
	}
	//Destructor
	streamEncrypter::~streamEncrypter()
	{
		delete [] ID_check;
	}
	//Encrypts an array
	uint8_t* streamEncrypter::sendData(uint8_t* array, size_t len, uint16_t& flag)
	{
		if(len>size::stream::PACKETSIZE) throw errorPointer(new bufferLargeError(),os::shared_type);

		//Check to ensure we have a good identifier
		streamPacket* en;
		bool packet_found = false;
		do
		{
			en = new streamPacket (cipher.get(), size::stream::PACKETSIZE);
			ID_check[last_loc] = (uint16_t) en->getIdentifier();

			int cnt = 0;
			packet_found = true;
			while(cnt<size::stream::BACKCHECK && packet_found)
			{
				if(ID_check[last_loc]==0 ||
					(last_loc!=cnt && ID_check[cnt] == ID_check[last_loc]))
				{
					packet_found = false;
				}
				++cnt;
			}

			if(!packet_found)
				delete(en);
		}
		while(!packet_found);

		//Encrypt and return
		last_loc=(last_loc+1) % size::stream::BACKCHECK;
		flag = (uint16_t) en->getIdentifier();
		en->encrypt(array, len);
		delete(en);
		return array;
	}

//Stream Decypter----------------------------------------------------------------------------

	//Constructor
	streamDecrypter::streamDecrypter(os::smart_ptr<streamCipher> c)
	{
		cipher = c;
		last_value = 0;
		mid_value = size::stream::LAGCATCH-1;
		packetArray = new streamPacket*[size::stream::DECRYSIZE];

		int cnt = 0;

		//Initialize packets to NULL
		while(cnt<size::stream::DECRYSIZE)
		{
			packetArray[cnt] = NULL;
			++cnt;
		}
		cnt=0;

		//Create the packetArray checks
		while(cnt<size::stream::DECRYSIZE)
		{
			bool good_packet;
			do
			{
				packetArray[cnt] = new streamPacket(cipher.get(), size::stream::PACKETSIZE);
				good_packet = true;

				if(packetArray[cnt]->getIdentifier()==0) good_packet = false;

				int cnt2 = 1;
				while(cnt2<size::stream::BACKCHECK && good_packet)
				{
					if(packetArray[(size::stream::DECRYSIZE+cnt-cnt2)%size::stream::DECRYSIZE]!=NULL &&
						packetArray[(size::stream::DECRYSIZE+cnt-cnt2)%size::stream::DECRYSIZE]->getIdentifier()==packetArray[cnt]->getIdentifier())
						good_packet = false;

					cnt2++;
				}
				if(!good_packet) delete(packetArray[cnt]);
			}
			while(!good_packet);
			++cnt;
		}
	}
	//Destructor
	streamDecrypter::~streamDecrypter()
	{
		unsigned int cnt = 0;
		while(cnt<size::stream::DECRYSIZE)
		{
			if(packetArray[cnt]!=NULL)delete(packetArray[cnt]);
			++cnt;
		}
		delete(packetArray);
		cipher=NULL;
	}
	//Encrypts an array
	uint8_t* streamDecrypter::recieveData(uint8_t* array, size_t len, uint16_t flag)
	{
		if(len>size::stream::PACKETSIZE) throw errorPointer(new bufferLargeError(),os::shared_type);

		//Find the flag
		int cnt = 2;
		bool found = false;
		while(cnt<size::stream::DECRYSIZE && !found)
		{
			if(packetArray[(cnt+last_value+size::stream::DECRYSIZE-size::stream::BACKCHECK)%size::stream::DECRYSIZE]->getIdentifier()==flag) found = true;
			if(!found) ++cnt;
		}

		//Check if we have found the packet
		if(!found) return NULL;

		//Preform the decryption
		packetArray[(cnt+last_value+size::stream::DECRYSIZE-size::stream::BACKCHECK)%size::stream::DECRYSIZE]->encrypt(array,len);

		//Change save array
		last_value = (cnt+last_value+size::stream::DECRYSIZE-size::stream::BACKCHECK)%size::stream::DECRYSIZE;
		//cryptoout<<"Last value:"<<last_value<<"\tMid value:"<<mid_value<<endl;
		if((last_value<mid_value && last_value>((mid_value-size::stream::LAGCATCH+size::stream::DECRYSIZE) % size::stream::DECRYSIZE)) ||
			(mid_value<((mid_value-size::stream::LAGCATCH+size::stream::DECRYSIZE) % size::stream::DECRYSIZE) && (last_value<mid_value || last_value>((mid_value-size::stream::LAGCATCH+size::stream::DECRYSIZE) % size::stream::DECRYSIZE)))||
		last_value==mid_value)
			return array;

		//Add the needed packets
		int difference = (last_value - mid_value+size::stream::DECRYSIZE)%size::stream::DECRYSIZE;
		cnt = 0;

		while(cnt<difference)
		{
			bool good_packet;
			//Confirm the packet is good
			do
			{
				good_packet = true;
				if(packetArray[(mid_value+size::stream::DECRYSIZE-size::stream::LAGCATCH+cnt+1)%size::stream::DECRYSIZE]!=NULL)
					delete(packetArray[(mid_value+size::stream::DECRYSIZE-size::stream::LAGCATCH+cnt+1)%size::stream::DECRYSIZE]);
				packetArray[(mid_value+size::stream::DECRYSIZE-size::stream::LAGCATCH+cnt+1)%size::stream::DECRYSIZE] = new streamPacket(cipher.get(), size::stream::PACKETSIZE);

				if(packetArray[(mid_value+size::stream::DECRYSIZE-size::stream::LAGCATCH+cnt+1)%size::stream::DECRYSIZE]->getIdentifier()==0)
					good_packet = false;
				int local_cnt = 1;
				while(good_packet&&local_cnt<size::stream::BACKCHECK)
				{
					if(packetArray[(mid_value+size::stream::DECRYSIZE-size::stream::LAGCATCH+cnt+1)%size::stream::DECRYSIZE]->getIdentifier()==
						packetArray[(mid_value+size::stream::DECRYSIZE-size::stream::LAGCATCH+cnt+1-local_cnt)%size::stream::DECRYSIZE]->getIdentifier())
						good_packet = false;
					++local_cnt;
				}
			}
			while(!good_packet);
			++cnt;
		}
		mid_value = last_value;

		return array;
	}

#endif

///@endcond