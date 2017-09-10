/**
 * Provides an interface to dump and
 * retrieve data from an encrypted
 * binary file without concern as to
 * the encryption algorithm used.
 **/

#ifndef BINARY_ENCRYPTION_H
#define BINARY_ENCRYPTION_H

#include "streamPackage.h"
#include "publicKeyPackage.h"
#include "cryptoError.h"
#include "keyBank.h"

namespace crypto {

	/** @brief Encrypted binary file output
	 *
	 * The user defines an encryption
	 * algorithm and key, then places
	 * data into the file.  This data is
	 * automatically encrypted with the
	 * specified algorithm and key.
	 */
	class binaryEncryptor: public errorSender
	{
		/** @brief Defines method of locking the file
		 */
		unsigned int _publicLockType;
		/** @brief Pointer to the mandatory stream algorithm definition
		 */
		os::smart_ptr<streamPackageFrame> _streamAlgorithm;
		/** @brief Pointer to the current stream cipher
		 *
		 * The current cipher will be of the type defined
		 * in the algorithm definition.  It will be initialized
		 * with either the provided public key or the
		 * provided password.
		 */
		os::smart_ptr<streamCipher> currentCipher;
		/** @brief State of the output file
		 *
		 * This state is either "good" or "bad."
		 * A bad file is not merely defined by
		 * crypto::binaryEncryptor::output, but
		 * also by any cryptographic abnormalities
		 * that are detected.
		 */
		bool _state;
		/** @brief Has the file been closed
		 *
		 * If true, the file is closed.  Else,
		 * the file is open and may be written to.
		 */
		bool _finished;
		/** @brief Name of the file being written to
		 */
		std::string _fileName;
		/** @brief Binary output file
		 */
		std::ofstream output;

		/** @brief Construct class with password
		 *
		 * This function acts as a constructor.
		 * It is only called by "true" constructors
		 * and exists to allow multiple data formats
		 * to be converted into the key.
		 *
		 * @param [in] key Array of characters defining the symmetric key
		 * @param [in] keyLen Length of symmetric key
		 * @return void
		 */
		void build(unsigned char* key,size_t keyLen);
		/** @brief Construct class with public key
		 *
		 * This function acts as a constructor.
		 * It is only called by "true" constructors
		 * and exists to allow multiple types of
		 * data to be converted to a public key.
		 *
		 * @param [in] publicKeyLock Public key pair to encrypt data
		 * @return void
		 */
		void build(os::smart_ptr<publicKey> publicKeyLock);
		/** @brief Construct class with number and algorithm
		 *
		 * This function acts as a constructor.
		 * It is only called by "true" constructors
		 * and exists to allow multiple types of
		 * data to be converted to a public key.
		 *
		 * @param [in] pubKey Public key to encrypt data
		 * @param [in] pkAlgo Algorithm ID
		 * @param [in] pkSize Size of public key
		 * @return void
		 */
		void build(os::smart_ptr<number> pubKey,unsigned int pkAlgo,size_t pkSize);
	public:
		/** @brief Construct with public key
		 *
		 * Constructs the file writer with a
		 * public key and an optional stream
		 * algorithm definition
		 *
		 * @param [in] file_name Name of output file
		 * @param [in] publicKeyLock Public key to encrypt data
		 * @param [in] lockType Defines method of locking with public key
		 * @param [in] stream_algo Optional stream algorithm definition
		 */
		binaryEncryptor(std::string file_name,os::smart_ptr<publicKey> publicKeyLock,unsigned int lockType=file::PRIVATE_UNLOCK,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		/** @brief Construct with number and public key algorithm
		 *
		 * Constructs the file writer with a
		 * public key and an optional stream
		 * algorithm definition
		 *
		 * @param [in] file_name Name of output file
		 * @param [in] publicKey Number to encrypt data
		 * @param [in] pkAlgo Defines public key algorithm
		 * @param [in] pkSize Defines size of public key
		 * @param [in] stream_algo Optional stream algorithm definition
		 */
		binaryEncryptor(std::string file_name,os::smart_ptr<number> publicKey,unsigned int pkAlgo,size_t pkSize,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		/** @brief Construct with password
		 *
		 * Constructs the file writer with a
		 * password and an optional stream
		 * algorithm definition
		 *
		 * @param [in] file_name Name of output file
		 * @param [in] password String to encrypt data with
		 * @param [in] stream_algo Optional stream algorithm definition
		 */
		binaryEncryptor(std::string file_name,std::string password,os::smart_ptr<streamPackageFrame> stream_algo=NULL);
		/** @brief Construct with symmetric key
		 *
		 * Constructs the file writer with a
		 * symmetric key and an optional stream
		 * algorithm definition
		 *
		 * @param [in] file_name Name of output file
		 * @param [in] key Array of characters defining the symmetric key
		 * @param [in] keyLen Length of symmetric key
		 * @param [in] stream_algo Optional stream algorithm definition
		 */
		binaryEncryptor(std::string file_name,unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> stream_algo=NULL);

		/** @brief Write a single character
		 *
		 * @param [in] data Character to write
		 * @return void
		 */
		void write(unsigned char data);
		/** @brief Write an array of bytes
		 *
		 * @param [in] data Data array to write
		 * @param [in] dataLen Length of data array
		 * @return void
		 */
		void write(const unsigned char* data,size_t dataLen);
		/** @brief Closes the output file
		 *
		 * @return void
		 */
		void close();

		/** @brief Returns the name of target file
		 *
		 * @return crypto::binaryEncryptor::_fileName
		 */
		const std::string& fileName() const {return _fileName;}
		/** @brief Returns the stream algorithm definition
		 *
		 * @return crypto::binaryEncryptor::_streamAlgorithm
		 */
		const os::smart_ptr<streamPackageFrame> streamAlgorithm() const {return _streamAlgorithm;}
		/** @brief Returns the current file state
		 *
		 * @return crypto::binaryEncryptor::_state
		 */
		bool good() const{return _state;}
		/** @brief Returns if the file has finished writing
		 *
		 * @return crypto::binaryEncryptor::_finished
		 */
		bool finished() const{return _finished;}

		/** @brief Virtual destructor
		 *
		 * Destructor must be virtual, if an object
		 * of this type is deleted, the destructor
		 * of the type which inherits this class should
		 * be called.  Also closes the output file.
		 */
		virtual ~binaryEncryptor(){close();}
	};

	///@cond INTERNAL
	    class keyBank;
		class nodeGroup;
    ///@endcond

	/** @brief Encrypted binary file output
	 *
	 * The user defines an encryption
	 * algorithm and key, then places
	 * data into the file.  This data is
	 * automatically encrypted with the
	 * specified algorithm and key.
	 */
	class binaryDecryptor: public errorSender
	{
		/** @brief Pointer to the optional public key
		 */
		os::smart_ptr<publicKey> _publicKeyLock;
		/** @brief Pointer to the key bank (to confirm public keys)
		 */
		os::smart_ptr<keyBank> _keyBank;
		/** @brief Pointer to the user which signed this file
		 *
		 * This is only populated if a key-bank
		 * is bound to the class.
		 */
		os::smart_ptr<nodeGroup> _author;
		/** @brief Pointer to the mandatory stream algorithm definition
		 */
		os::smart_ptr<streamPackageFrame> _streamAlgorithm;
		/** @brief Pointer to the current stream cipher
		 *
		 * The current cipher will be of the type defined
		 * in the algorithm definition.  It will be initialized
		 * with either the provided public key or the
		 * provided password.
		 */
		os::smart_ptr<streamCipher> currentCipher;
		/** @brief State of the output file
		 *
		 * This state is either "good" or "bad."
		 * A bad file is not merely defined by
		 * crypto::binaryEncryptor::input, but
		 * also by any cryptographic abnormalities
		 * that are detected.
		 */
		bool _state;
		/** @brief Has the file been closed
		 *
		 * If true, the file is closed.  Else,
		 * the file is open and may be read from.
		 */
		bool _finished;
		/** @brief Name of the file being read from
		 */
		std::string _fileName;
		/** @brief Binary input file
		 */
		std::ifstream input;
		/** @brief Number of bytes left in the file
		 */
		size_t _bytesLeft;

		/** @brief Central constructor function
		 *
		 * This function reads the header of the
		 * encrypted binary file and attempts to
		 * initialize a stream cipher for decryption.
		 * Note that there is no guarantee that this
		 * can be done with the information given to
		 * the class.  In this event, the class logs
		 * the error and sets it's state to false.
		 *
		 * @param [in] key Symmetric key, NULL by default
		 * @param [in] keyLen Length of symmetric key, 0 by default
		 * @return void
		 */
		void build(unsigned char* key=NULL,size_t keyLen=0);
	public:
		/** @brief Construct with public key
		 *
		 * Constructs the file reader with a
		 * public key.
		 *
		 * @param [in] file_name Name of input file
		 * @param [in] kBank Record of public keys
		 */
		binaryDecryptor(std::string file_name,os::smart_ptr<keyBank> kBank);
		/** @brief Construct with public key
		 *
		 * Constructs the file reader with a
		 * public key.
		 *
		 * @param [in] file_name Name of input file
		 * @param [in] publicKeyLock Public key to decrypt data
		 */
		binaryDecryptor(std::string file_name,os::smart_ptr<publicKey> publicKeyLock);
		/** @brief Construct with password
		 *
		 * Constructs the file reader with a
		 * password.
		 *
		 * @param [in] file_name Name of input file
		 * @param [in] password Password to decrypt data
		 */
		binaryDecryptor(std::string file_name,std::string password);
		/** @brief Construct with symmetric key
		 *
		 * Constructs the file reader with a
		 * symmetric key.
		 *
		 * @param [in] file_name Name of input file
		 * @param [in] key Symmetric key byte array
		 * @param [in] keyLen Size of the symmetric key
		 */
		binaryDecryptor(std::string file_name,unsigned char* key,size_t keyLen);

		/** @brief Attempts to read a single character
		 *
		 * Note that if the reader is in a "good"
		 * state, then this function will read and
		 * decrypt a single byte of the file.
		 *
		 * @return Character read, 0 if failed
		 */
		unsigned char read();
		/** @brief Attempts to read a block of data
		 *
		 * Note that if the reader is in a "good"
		 * state, then this function will read and
		 * decrypt the entire block of data requested.
		 *
		 * @param [out] data Array to place read data into
		 * @param [in] dataLen Number of bytes attempting to read
		 * @return Number of bytes read
		 */
		size_t read(unsigned char* data,size_t dataLen);
		/** @brief Closes the output file
		 *
		 * @return void
		 */
		void close();

		/** @brief Returns the name of target file
		 *
		 * @return crypto::binaryDecryptor::_fileName
		 */
		const std::string& fileName() const {return _fileName;}
		/** @brief Returns the stream algorithm definition
		 *
		 * @return crypto::binaryDecryptor::_streamAlgorithm
		 */
		const os::smart_ptr<streamPackageFrame> streamAlgorithm() const {return _streamAlgorithm;}
		/** @brief Returns the current file state
		 *
		 * @return crypto::binaryDecryptor::_state
		 */
		bool good() const{return _state;}
		/** @brief Returns if the file has finished writing
		 *
		 * @return crypto::binaryDecryptor::_finished
		 */
		bool finished() const{return _finished;}
		/** @brief Returns the number of bytes left in the file
		 *
		 * @return crypto::binaryDecryptor::_bytesLeft
		 */
		inline size_t bytesLeft() const {return _bytesLeft;}
		/** @brief Pointer to the user which signed this file
		 * @return crypto::binaryDecryptor::_author
		 */
		os::smart_ptr<nodeGroup> author();
		/** @brief Virtual destructor
		 *
		 * Destructor must be virtual, if an object
		 * of this type is deleted, the destructor
		 * of the type which inherits this class should
		 * be called.  Also closes the input file.
		 */
		virtual ~binaryDecryptor();
	};
}

#endif
