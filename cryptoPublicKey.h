/**
 * Contains declarations of the generalized
 * public key and the RSA public key.  These
 * classes can both encrypt and decrypt
 * public keys.
 *
 */

#ifndef CRYPTO_PUBLIC_KEY_H
#define CRYPTO_PUBLIC_KEY_H

#include "Datastructures/Datastructures.h"
#include "cryptoNumber.h"
#include "streamPackage.h"
#include "osMechanics/osMechanics.h"

namespace crypto
{
	///@cond INTERNAL
	class publicKey;
	class keyChangeSender;
	///@endcond

	/** @brief Interface for receiving key changes
	 *
	 * A class which is alerted by public keys
	 * when the public key is updated.
	 */
	class keyChangeReceiver: public os::eventReceiver<keyChangeSender>
	{
	protected:
		/** @brief Allows access to crypto::keyChangeReceiver::publicKeyChanged
		 */
		friend class keyChangeSender;
		/** @brief Triggers on key change
		 *
		 * Is triggered by crypto::publicKey whenever the public key
		 * is updated.
		 *
		 * @param [in] pbk Public key which was changed
		 * @return void
		 */
		virtual void publicKeyChanged(os::smart_ptr<publicKey> pbk){}
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~keyChangeReceiver(){}
		/** @brief Equality test
		 */
		virtual bool operator==(const keyChangeReceiver& l) const{return this==&l;}
		/** @brief Greater than test
		 */
		virtual bool operator>(const keyChangeReceiver& l) const{return this>&l;}
		/** @brief Less than test
		 */
		virtual bool operator<(const keyChangeReceiver& l) const{return this<&l;}
		/** @brief Greater than/equal to test
		 */
		virtual bool operator>=(const keyChangeReceiver& l) const{return this>=&l;}
		/** @brief Less than/equal to test
		 */
		virtual bool operator<=(const keyChangeReceiver& l) const{return this<=&l;}
	};

	/** @brief Interface inherited by publicKey
	 *
	 * This class is meaningless outside of
	 * crypto::publicKey and is only designed
	 * to be inherited by publicKey to
	 * interface with crypto::keyChangeReceiver.
	 */
	class keyChangeSender: public os::eventSender<keyChangeReceiver>
	{
	protected:
		/** @brief Sends key change event to listeners
		 *
		 * Useing the interface provided by the os::eventSender class,
		 * alert any classes listening for a public key change that one has occured.
		 *
		 * @param [in] ptr Receiver to alert
		 * @return void
		 */
		void sendEvent(os::smart_ptr<keyChangeReceiver> ptr){ptr->publicKeyChanged((publicKey*)this);}
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~keyChangeSender(){}

		/** @brief Equality test
		 */
		virtual bool operator==(const keyChangeSender& l) const{return this==&l;}
		/** @brief Greater than test
		 */
		virtual bool operator>(const keyChangeSender& l) const{return this>&l;}
		/** @brief Less than test
		 */
		virtual bool operator<(const keyChangeSender& l) const{return this<&l;}
		/** @brief Greater than/equal to test
		 */
		virtual bool operator>=(const keyChangeSender& l) const{return this>=&l;}
		/** @brief Less than/equal to test
		 */
		virtual bool operator<=(const keyChangeSender& l) const{return this<=&l;}
	};

	/** @brief Base public-key class
	 *
	 * Class which defines the general
	 * structure of a public-private
	 * key pair.  The class does not
	 * define the specifics of the algorithm.
	 */
	class publicKey: public os::savable, public keyChangeSender
	{
		/**@ brief Size of the keys used
		 */
		uint16_t _size;
		/**@ brief ID of algorithm used
		 */
		uint16_t _algorithm;
		/**@ brief Number of historical keys to keep
		 */
        size_t _history;

		/** @brief Symmetric key for encryption
		 */
		unsigned char* _key;
		/** @brief Length of symmetric key
		 */
		size_t _keyLen;
		/**@ brief Algorithm used for encryption
		 */
		os::smart_ptr<streamPackageFrame> fePackage;
		/**@ brief Name of file this key is saved to
		 */
		std::string _fileName;
		/**@ brief Mutex for replacing the keys
		 */
		os::readWriteLock keyLock;
	protected:
		/**@ brief Public key
		 */
        os::smart_ptr<number> n;
		/**@ brief Private key
		 */
        os::smart_ptr<number> d;
		/**@ brief Date/time keys created
		 */
		uint64_t _timestamp;

		/**@ brief List of old public keys
		 */
        os::pointerUnsortedList<number> oldN;
		/**@ brief List of old private keys
		 */
        os::pointerUnsortedList<number> oldD;
		/**@ brief List of time-stamps for old pairs
		 */
		os::pointerUnsortedList<uint64_t> _timestamps;

		/** @brief No key constructor
		 *
		 * @param algo Algorithm ID
		 * @param sz Size of key, size::public512 by default
		 */
		publicKey(uint16_t algo,uint16_t sz=size::public512);
		/** @brief Copy constructor
		 *
		 * @param ky Public key to be copied
		 */
        publicKey(const publicKey& ky);
		/** @brief Construct with keys
		 *
		 * @param _n Smart pointer to public key
		 * @param _d Smart pointer to private key
		 * @param algo Algorithm ID
		 * @param sz Size of key, size::public512 by default
		 * @param tms Time-stamp of the current keys, now by default
		 */
		publicKey(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint16_t algo,uint16_t sz=size::public512,uint64_t tms=os::getTimestamp());
		/** @brief Construct with path to file and password
		 *
		 * @param algo Algorithm ID
		 * @param fileName Name of file to find keys
		 * @param password String representing symmetric key, "" by default
		 * @param stream_algo Symmetric key encryption algorithm, NULL by default
		 */
		publicKey(uint16_t algo,std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		/** @brief Construct with path to file and password
		 *
		 * @param algo Algorithm ID
		 * @param fileName Name of file to find keys
		 * @param key Symmetric key
		 * @param keyLen Length of symmetric key
		 * @param stream_algo Symmetric key encryption algorithm, NULL by default
		 */
		publicKey(uint16_t algo,std::string fileName,unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);

		/** @brief Locks the write lock
		 * @return void
		 */
		inline void writeLock() {keyLock.lock();}
		/** @brief Unlocks the write lock
		 * @return void
		 */
		inline void writeUnlock() {keyLock.unlock();}
	public:
		/** @brief Increments the read-lock
		 * @return void
		 */
		inline void readLock() {keyLock.increment();}
		/** @brief Decrements the read-lock
		 * @return void
		 */
		inline void readUnlock() {keyLock.decrement();}
	protected:
		/** @brief Bind old keys to history
		 *
		 * @param [in] n Old public key
		 * @param [in] d Old private key
		 * @param [in] ts Old time-stamp
		 * @return void
		 */
        void pushOldKeys(os::smart_ptr<number> n, os::smart_ptr<number> d,uint64_t ts);
    public:
		/** @brief Current key index
		 * Allows the current key to be accessed
		 * as historical index '-1'
		 */
		static const size_t CURRENT_INDEX = ~0;
		/** @brief Public boolean marker
		 */
		static const bool PUBLIC=true;
		/** @brief Private boolean marker
		 */
		static const bool PRIVATE=false;
		/** @brief N (public) boolean marker
		 */
		static const bool N_MARKER=true;
		/** @brief D (private) boolean marker
		 */
		static const bool D_MARKER=false;

		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~publicKey() throw();

		/** @brief Searches for key by hash
		 *
		 * Binds the location that the keys were found
		 * in to the arguments of the function.
		 *
		 * @param [in] hsh Hash of the key to be searched for
		 * @param [out] hist History value the key was found
		 * @param [out] type Type (public or private)
		 * @return True if the key was found, else, false
		 */
		bool searchKey(hash hsh, size_t& hist,bool& type);
		/** @brief Searches for key
		 *
		 * Binds the location that the keys were found
		 * in to the arguments of the function.
		 *
		 * @param [in] num Key to search for
		 * @param [out] hist History value the key was found
		 * @param [out] type Type (public or private)
		 * @return True if the key was found, else, false
		 */
		bool searchKey(os::smart_ptr<number> key, size_t& hist,bool& type);
		/** @brief Converts number to correct type
		 * @param [in] num Number to be converted
		 * @return Converted number
		 */
		virtual os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
		/** @brief Converts array to correct number type
		 * @param [in] arr Array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
        virtual os::smart_ptr<number> copyConvert(const uint32_t* arr,size_t len) const;
		/** @brief Converts byte array to correct number type
		 * @param [in] arr Byte array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
        virtual os::smart_ptr<number> copyConvert(const unsigned char* arr,size_t len) const;

		/** @brief Converts number to correct type, statically
		 * @param [in] num Number to be converted
		 * @return Converted number
		 */
		static os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num,uint16_t size);
		/** @brief Converts array to correct number type, statically
		 * @param [in] arr Array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
		static os::smart_ptr<number> copyConvert(const uint32_t* arr,size_t len,uint16_t size);
		/** @brief Converts byte array to correct number type, statically
		 * @param [in] arr Byte array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
		static os::smart_ptr<number> copyConvert(const unsigned char* arr,size_t len,uint16_t size);

		/** @brief Public key access
		 * @return crypto::publicKey::n
		 */
		os::smart_ptr<number> getN() const;
		/** @brief Private key access
		 * @return crypto::publicKey::d
		 */
		os::smart_ptr<number> getD() const;
		/** @brief Time-stamp access
		 * @return crypto::publicKey::_timestamp
		 */
		uint64_t timestamp() const {return _timestamp;}
		/** @brief Access old public keys
		 * @param history Historical index, 0 by default
		 * @return Public key at given index
		 */
		os::smart_ptr<number> getOldN(size_t history=0);
		/** @brief Access old private keys
		 * @param history Historical index, 0 by default
		 * @return Private key at given index
		 */
		os::smart_ptr<number> getOldD(size_t history=0);
		/** @brief Access old time-stamps
		 * @param history Historical index, 0 by default
		 * @return Time-stamp at given index
		 */
		uint64_t getOldTimestamp(size_t history=0);
		/** @brief Key generation function
		 *
		 * Generates new keys for the specific
		 * algorithm.  This is re-implemented
		 * by every algorithm.
		 *
		 * @return void
		 */
		virtual void generateNewKeys();
		/** @brief Tests if the keys are in the process of generating
		 * @return True if generating new keys
		 */
        virtual bool generating() {return false;}
		/** @brief Access algorithm ID
		 * @return crypto::algo::publicNULL
		 */
		inline static uint16_t staticAlgorithm() {return algo::publicNULL;}
		/** @brief Access algorithm name
		 * @return "NULL Public Key"
		 */
        inline static std::string staticAlgorithmName() {return "NULL Public Key";}
		/** @brief Access algorithm ID
		 * @return crypto::publicKey::_algorithm
		 */
		inline uint16_t algorithm() const {return _algorithm;}
		/** @brief Access algorithm name
		 * @return crypto::publicKey::staticAlgorithmName()
		 */
		inline virtual std::string algorithmName() const {return publicKey::staticAlgorithmName();}
		/** @brief Access key size
		 * @return crypto::publicKey::_size
		 */
        uint16_t size() const {return _size;}

        /** @brief Sets history size
		 *
		 * Determines the number of historical keys to
		 * keep recorded.  Note that keys are sorted
		 * by the order they were received into this
		 * structure, not their time-stamp.
		 *
		 * @param [in] hist History size to be bound
		 * @return void
		 */
        void setHistory(size_t hist);
		/** @breif Access history size
		 * @return crypto::publicKey::_history
		 */
        inline size_t history() const {return _history;}

		/** @brief Re-save the entire structure
		 * @return void
		 */
		void save();
		/** @brief Loads the structure from a file
		 * @return void
		 */
        void loadFile();
		/** @brief Set the save file name
		 * @param [in] fileName Path of save file
		 * @return void
		 */
		void setFileName(std::string fileName);
		/** @brief Binds a new symmetric key
		 *
		 * Re-binding of the symmetric key will
		 * result in a re-save event through the
		 * savable class.
		 *
		 * @param [in] key Symmetric key
		 * @param [in] keyLen Length of symmetric key
		 * @return void
		 */
		void setPassword(unsigned char* key,size_t keyLen);
		/** @breif Binds a new symmetric key
		 *
		 * @param [in] password String representing the symmetric key
		 * @return void
		 */
		void setPassword(std::string password);
		/** @brief Sets the symmetric encryption algorithm
		 * @param [in] stream_algo Symmetric key algorithm
		 * @return void
		 */
		void setEncryptionAlgorithm(os::smart_ptr<streamPackageFrame> stream_algo);
		/** @brief Return the save file path
		 * @return crypto::publicKey::_fileName
		 */
		const std::string& fileName() const {return _fileName;}
		/** @brief Add key pair
		 *
		 * Adds a key-pair and binds the current keys
		 * to the history;.
		 *
		 * @param _n Smart pointer to public key
		 * @param _d Smart pointer to private key
		 * @param tms Time-stamp of the current keys, now by default
		 *
		 * @return void
		 */
		void addKeyPair(os::smart_ptr<number> _n,os::smart_ptr<number> _d,uint64_t tms=os::getTimestamp());

		/** @brief Static number encode
		 *
		 * This function is expected to be re-implemented
		 * for each public-key type.  This function must be
		 * static because data can be encoded with a public
		 * key even though a node does not have its own keys defined.
		 *
		 * @param [in] code Data to be encoded
		 * @param [in] publicN Public key to be encoded against
		 * @param [in] size Size of key used
		 * @return Encoded number
		 */
        static os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN, uint16_t size);
		/** @brief Hybrid data encode against number
		 *
		 * This function is expected to be re-implemented
		 * for each public-key type.  This function must be
		 * static because data can be encoded with a public
		 * key even though a node does not have its own keys defined.
		 *
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against, NULL by default
		 * @param [in] size Size of key used
		 * @return void
		 */
		static void encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN, uint16_t size);
        /** @brief Static data encode
		 *
		 * This function is expected to be re-implemented
		 * for each public-key type.  This function must be
		 * static because data can be encoded with a public
		 * key even though a node does not have its own keys defined.
		 *
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against
		 * @param [in] nLength Length of key array
		 * @param [in] size Size of key used
		 * @return void
		 */
		static void encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength, uint16_t size);

		/** @brief Number encode
		 * @param [in] code Data to be encoded
		 * @param [in] publicN Public key to be encoded against, NULL by default
		 * @return Encoded number
		 */
		virtual os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN=NULL) const;
		/** @brief Data encode against number
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against, NULL by default
		 * @return void
		 */
		virtual void encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN=NULL) const;
		/** @brief Data encode
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against
		 * @param [in] nLength Length of key array
		 * @return void
		 */
		virtual void encode(unsigned char* code,size_t codeLength, unsigned const char* publicN, size_t nLength) const;
		/** @brief Number decode
		 *
		 * Uses the private key to decode a
		 * set of data.  Re-implemented by
		 * algorithm definitions which inherit
		 * from this class.
		 *
		 * @param  [in] code Data to be decoded
		 * @return Decoded number
		 */
		virtual os::smart_ptr<number> decode(os::smart_ptr<number> code) const;
		/** @brief Number decode, old key
		 *
		 * Uses the private key to decode a
		 * set of data.  Re-implemented by
		 * algorithm definitions which inherit
		 * from this class.
		 *
		 * @param  [in] code Data to be decoded
		 * @param [in] hist Index of historical key
		 * @return Decoded number
		 */
		virtual os::smart_ptr<number> decode(os::smart_ptr<number> code, size_t hist);
		/** @brief Data decode
		 *
		 * Uses the private key to decode a
		 * set of data.
		 *
		 * @param [in/out] code Data to be decoded
		 * @param [in] codeLength Length of code to be decoded
		 * @return void
		 */
        void decode(unsigned char* code, size_t codeLength) const;
		/** @brief Data decode, old key
		 *
		 * Uses the private key to decode a
		 * set of data.
		 *
		 * @param [in/out] code Data to be decoded
		 * @param [in] codeLength Length of code to be decoded
		 * @param [in] hist Index of historical key
		 * @return void
		 */
        void decode(unsigned char* code, size_t codeLength, size_t hist);

        /** @brief Compare this with another public key
         *
         * Compares based on the algorithm ID and size of
         * the key.  Note that this will return 0 if two
         * public keys have the same algorithm ID and size
         * even if they have different keys.
         *
         * @param [in] cmp Public key to compare against
         * @return 0 if equal, 1 if greater than, -1 if less than
         */
        int compare(const publicKey& cmp) const;

        /** @brief Cast nodeNameReference to size_t
         * @return Hashed location of nodeNameReference
         */
        inline operator size_t() const {return _size<<4 & _algorithm;}

        #undef CURRENT_CLASS
        #define CURRENT_CLASS publicKey
        COMPARE_OPERATORS
	};
    ///@cond INTERNAL
	class RSAKeyGenerator;
	///@endcond

	/** @brief RSA public-key encryption
	 *
	 * This class defines an RSA algorithm
	 * for public-key cryptography.
	 */
	class publicRSA: public publicKey
	{
		/** @brief Friendship with key generation
		 *
		 * The crypto::RSAKeyGenerator must be able
		 * to access the private members of the RSA
		 * public key class to bind newly generated keys.
		 */
		friend class RSAKeyGenerator;
		/** @brief Used in intermediate calculation
		 */
		integer e;
		/** @brief Key generation class
		 *
		 * This pointer will be NULL unless a
		 * key is currently being generated/
		 */
		os::smart_ptr<RSAKeyGenerator> keyGen;
		/** @brief Subroutine initializing crypto::publicRSA::e
		 */
		void initE();
	public:
		/** @brief Default RSA constructor
		 *
		 * Initializes and generates keys for
		 * a new pair of RSA keys.  This serves
		 * as the default constructor for RSA keys.
		 *
		 * @param [in] sz Size of keys, crypto::size::public256 by default
		 */
	    publicRSA(uint16_t sz=size::public256);
		/** @brief Copy Constructor
		 *
		 * Copies the keys in one RSA pair into
		 * another.  This copying includes all
		 * historical records as well.
		 *
		 * @param [in] ky Key pair to be copied
		 */
	    publicRSA(publicRSA& ky);
		/** @brief Construct with keys
		 *
		 * @param _n Smart pointer to public key
		 * @param _d Smart pointer to private key
		 * @param sz Size of key, size::public512 by default
		 * @param tms Time-stamp of the current keys, now by default
		 */
	    publicRSA(os::smart_ptr<integer> _n,os::smart_ptr<integer> _d,uint16_t sz=size::public512,uint64_t tms=os::getTimestamp());
		/** @brief Construct with key arrays
		 *
		 * @param _n Array of public key
		 * @param _d Array of private key
		 * @param sz Size of key, size::public512 by default
		 * @param tms Time-stamp of the current keys, now by default
		 */
		publicRSA(uint32_t* _n,uint32_t* _d,uint16_t sz=size::public512,uint64_t tms=os::getTimestamp());
		/** @brief Construct with path to file and password
		 *
		 * @param fileName Name of file to find keys
		 * @param password String representing symmetric key, "" by default
		 * @param stream_algo Symmetric key encryption algorithm, NULL by default
		 */
	    publicRSA(std::string fileName,std::string password="",os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		/** @brief Construct with path to file and password
		 *
		 * @param fileName Name of file to find keys
		 * @param key Symmetric key
		 * @param keyLen Length of symmetric key
		 * @param stream_algo Symmetric key encryption algorithm, NULL by default
		 */
	    publicRSA(std::string fileName,unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);

		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
	    virtual ~publicRSA(){}

		/** @brief Converts number to integer
		 * @param [in] num Number to be converted
		 * @return Converted number
		 */
		os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num) const;
	    /** @brief Converts array to integer
		 * @param [in] arr Array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
		os::smart_ptr<number> copyConvert(const uint32_t* arr,size_t len) const;
	    /** @brief Converts byte array to integer
		 * @param [in] arr Byte array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
		os::smart_ptr<number> copyConvert(const unsigned char* arr,size_t len) const;

		/** @brief Converts number to integer, statically
		 * @param [in] num Number to be converted
		 * @return Converted number
		 */
	    static os::smart_ptr<number> copyConvert(const os::smart_ptr<number> num,uint16_t size);
	    /** @brief Converts array to integer, statically
		 * @param [in] arr Array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
		static os::smart_ptr<number> copyConvert(const uint32_t* arr,size_t len,uint16_t size);
	    /** @brief Converts byte array to integer, statically
		 * @param [in] arr Byte array to be converted
		 * @param [in] len Length of array to be converted
		 * @return Converted number
		 */
		static os::smart_ptr<number> copyConvert(const unsigned char* arr,size_t len,uint16_t size);

		/** @brief Access algorithm ID
		 * @return crypto::algo::publicRSA
		 */
		inline static uint16_t staticAlgorithm() {return algo::publicRSA;}
	    /** @brief Access algorithm name
		 * @return "RSA"
		 */
		inline static std::string staticAlgorithmName() {return "RSA";}
		/** @brief Access algorithm name
		 * @return crypto::publicRSA::staticAlgorithmName()
		 */
		inline std::string algorithmName() const {return publicRSA::staticAlgorithmName();}
	    /** @brief Tests if the keys are in the process of generating
		 * @return True if generating new keys
		 */
		bool generating();
		/** @brief Key generation function
		 *
		 * Generates new keys for the specific
		 * algorithm.  This is re-implemented
		 * by every algorithm.
		 *
		 * @return void
		 */
		void generateNewKeys();

	    /** @brief Static number encode
		 *
		 * Encodes based on the RSA algorithm.  This function
		 * must be static because data can be encoded with a
		 * public key even though a node does not have its
		 * own keys defined.
		 *
		 * @param [in] code Data to be encoded
		 * @param [in] publicN Public key to be encoded against
		 * @param [in] size Size of key used
		 * @return Encoded number
		 */
	    static os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN, uint16_t size);
		/** @brief Static data encode
		 *
		 * Encodes based on the RSA algorithm.  This function
		 * must be static because data can be encoded with a
		 * public key even though a node does not have its
		 * own keys defined.
		 *
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against
		 * @param [in] size Size of key used
		 * @return void
		 */
		static void encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN, uint16_t size);
	    /** @brief Static data encode
		 *
		 * Encodes based on the RSA algorithm.  This function
		 * must be static because data can be encoded with a
		 * public key even though a node does not have its
		 * own keys defined.
		 *
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against
		 * @param [in] nLength Length of key array
		 * @param [in] size Size of key used
		 * @return void
		 */
		static void encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength, uint16_t size);

		/** @brief Number encode
		 * @param [in] code Data to be encoded
		 * @param [in] publicN Public key to be encoded against, NULL by default
		 * @return Encoded number
		 */
	    os::smart_ptr<number> encode(os::smart_ptr<number> code, os::smart_ptr<number> publicN=NULL) const;
	    /** @brief Hybrid data encode against number
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against, NULL by default
		 * @return void
		 */
		void encode(unsigned char* code, size_t codeLength, os::smart_ptr<number> publicN=NULL) const;
		/** @brief Data encode against number
		 * @param [in/out] code Data to be encoded
		 * @param [in] codeLength Length of code array
		 * @param [in] publicN Public key to be encoded against, NULL by default
		 * @return void
		 */
		void encode(unsigned char* code, size_t codeLength, unsigned const char* publicN, size_t nLength) const;

		/** @brief Number decode
		 *
		 * Uses the private key to decode a
		 * set of data based on the RSA
		 * algorithm.
		 *
		 * @param  [in] code Data to be decoded
		 * @return Decoded number
		 */
	    os::smart_ptr<number> decode(os::smart_ptr<number> code) const;
		/** @brief Old number decode
		 *
		 * Uses old private keys to decode a
		 * set of data based on the RSA
		 * algorithm.
		 *
		 * @param  [in] code Data to be decoded
		 * @param [in] hist Index of historical key
		 * @return Decoded number
		 */
	    os::smart_ptr<number> decode(os::smart_ptr<number> code, size_t hist);
	};
	/** @brief Helper key generation class
	 *
	 * This class helps to generate
	 * RSA keys.  Once keys are generated,
	 * this class is destroyed.
	 */
	class RSAKeyGenerator
	{
		/** @brief Pointer to keys
		 *
		 * Points to the RSA keys this
		 * generator will be placing
		 * its generated keys into.
		 */
		publicRSA* master;

	public:
		/** @brief Intermediate prime
		 */
		integer p;
		/** @brief Intermediate prime
		 */
		integer q;

		/** @brief Constructs a generator with an RSA key
		 *
		 * This class is meaningless without a
		 * a reference to an RSA key to bind
		 * newly created keys to.
		 */
		RSAKeyGenerator(publicRSA& m);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~RSAKeyGenerator(){}

		/** @brief Generates a prime number
		 * @return Prime integer
		 */
		integer generatePrime();
		/** @brief Bind generated keys to master
         * @return void
         */
		void pushValues();
	};

};

#endif