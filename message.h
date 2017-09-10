/**
 * The message declared in this
 * file acts as a message for
 * the Crypto-Gateway.  These messages
 * are intended to be converted to
 * machine-to-machine communication.
 *
 */

#ifndef MESSAGE_H
#define MESSAGE_H

#include "Datastructures/Datastructures.h"

namespace crypto {

	///@cond INTERNAL
	class gatewaySettings;
	class gateway;
	///@endcond

	/** @brief Crypto-Gateway message
	 *
	 * This message is meant to be
	 * passed between machines.  The
	 * gateway either encrypts or
	 * decrypts the message.  This message
	 * allows for nested encryption.
	 */
	class message
	{
		/** @brief Friendship with settings
		 *
		 * The crypto::gatewaySettings class must be
		 * able to access the intrinsics of this class
		 * inorder to create and parse a ping message.
		 */
		friend class gatewaySettings;
		/** @brief Friendship with gateway
		 *
		 * The crypto::gateway class encrypts and decrypts
		 * messages, so it must be able to access the intrisics
		 * of the message.
		 */
		friend class gateway;

		/** @brief Size of message
		 *
		 * This size refers to the size of the
		 * non-header and non-checksum bytes in
		 * the message.  This value remains constant
		 * as messages are encrypted and decrypted.
		 */
		size_t _messageSize;
		/** @brief Size of the message packet
		 *
		 * This size includes all support data
		 * along with the meaningful message.
		 */
		size_t _size;
		/** @brief Depth of encryption
		 *
		 * Holds how many times this particular
		 * message has been encrypted.
		 */
		uint16_t _encryptionDepth;
		/** @brief Data in the message packet
		 */
		uint8_t* _data;
	public:
		/** @brief Constructs an encrypted message
		 *
		 * Parses an array of data assuming that the
		 * data in question has come out of another
		 * gateway.
		 *
		 * @param [in] rawData Incoming data array
		 * @param [in] sz Size of incoming data
		 *
		 * @return New message
		 */
		static message encryptedMessage(uint8_t* rawData,size_t sz);
		/** @brief Constructs an decrypted message
		 *
		 * Parses an array of data assuming that the
		 * data in question has been generated outside
		 * of a gateway
		 *
		 * @param [in] rawData Incoming data array
		 * @param [in] sz Size of incoming data
		 *
		 * @return New message
		 */
		static message decryptedMessage(uint8_t* rawData,size_t sz);

		/** @brief Constructs message with a size
		 * @param [in] sz Size of message
		 */
		message(size_t sz);
		/** @brief Copy constructor
		 * @param [in] msg Message to be copied
		 */
		message(const message& msg);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~message(){delete [] _data;}

		/** @brief Return message size
		 * @return message::_messageSize
		 */
		inline size_t messageSize() const {return _messageSize;}
		/** @brief Return message packet size
		 * @return message::_size
		 */
		inline size_t size() const {return _size;}
		/** @brief Return level of message encryption
		 * @return message::_encryptionDepth
		 */
		inline uint16_t encryptionDepth() const {return _encryptionDepth;}
		/** @brief Modifiable data pointer
		 * @return message::_data
		 */
		inline uint8_t* data() {return _data;}
		/** @brief Immutable data pointer
		 * @return message::_data
		 */
		inline const uint8_t* data() const {return _data;}
		/** @brief Is the message encrypted
		 * @return True if encrypted, else, false
		 */
		inline bool encrypted() const {return _encryptionDepth;}
		/** @brief Add string to this message
		 * @return True if successful
		 */
		bool pushString(std::string s);
		/** @brief Remove string from this message
		 * @return Next string to remove
		 */
		std::string popString();

		/** @brief Blocked message tag
		 *
		 * Indicates that the node sending
		 * the particular message has blocked
		 * the node receiving the particular
		 * message.
		 */
		static const uint8_t BLOCKED=0;
		/** @brief Ping message tag
		 *
		 * Message type sent by gateways
		 * when exchanging names and public
		 * keys.
		 */
		static const uint8_t PING=1;
		/** @brief Forward message tag
		 *
		 * Indicates a message is being sent through
		 * this gateway to another gateway for final
		 * decryption.
		 */
		static const uint8_t FORWARD=2;
		/** @brief Stream key message tag
		 *
		 * Indicates a message is exchanging
		 * stream cipher keys through the defined
		 * public key algorithm.
		 */
		static const uint8_t STREAM_KEY=3;
		/** @brief Signing message tag
		 *
		 * Indicates a message is cryptographically
		 * establishing the identity of a node.
		 */
		static const uint8_t SIGNING_MESSAGE=4;
		/** @brief Secure data exchange message tag
		 *
		 * Message passed between two gateways
		 * when secure.  Used by the gateways
		 * to notify connected gateways when
		 * keys and algorithms change after
		 * a connection has been secured.
		 */
		static const uint8_t SECURE_DATA_EXCHANGE=5;

		/** @brief Confirm error message tag
		 *
		 * Messages of this type are sent to
		 * allow the receiving gateway to know
		 * that the sending gateway has acknowledged
		 * its error.
		 */
		static const uint8_t CONFIRM_ERROR=252;
		/** @brief Basic error message tag
		 *
		 * Sent by a gateway when a basic error
		 * occurs.
		 */
		static const uint8_t BASIC_ERROR=253;
		/** @brief Timeout error message tag
		 *
		 * Sent by a gateway when a timeout error
		 * occurs.  Timeout errors are more serious and
		 * take a certain amount of time to expire.
		 */
		static const uint8_t TIMEOUT_ERROR=254;
		/** @brief Permenant error message tag
		 *
		 * Sent by a gateway when a permenant error has
		 * occurred.  Permenant errors never expire, and
		 * a gateway will never reconnect once a permenant
		 * error has occurred.
		 */
		static const uint8_t PERMENANT_ERROR=255;
	};
}

#endif
