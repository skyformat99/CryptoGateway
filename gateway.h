/**
 * Note that due to development constraints,
 * the gatewaySettings class is being pushed
 * out in a frame-work form and is intended
 * to contain a large set of algorithm definitions
 * as well as an algorithm use agreement protocol.
 *
 */

#ifndef GATEWAY_H
#define GATEWAY_H

#include "binaryEncryption.h"
#include "cryptoLogging.h"
#include "cryptoError.h"

#include "streamPackage.h"
#include "publicKeyPackage.h"
#include "message.h"

namespace crypto {

	///@cond INTERNAL
	class user;
	///@endcond

	/** @brief Holds settings for gateway encryption
	 *
	 * Contains all of the information needed to define
	 * how the gateway functions.  This includes which
	 * algorithms are white-listed, which are black-
	 * listed and which are preferred.  Note that this
	 * settings class can define the settings for a node
	 * whose private key is known or for a node whose
	 * private key is unknown.
	 */
	class gatewaySettings: public keyChangeReceiver, public os::savable
	{
		/** @brief Group ID of the node, unique to this settings class
		 */
		std::string _groupID;
		/** @brief Name of the node, defined by the user
		 */
		std::string _nodeName;
		/** @brief Save file path
		 *
		 * If the setting was defined by the user and
		 * not a "ping" message, it will often have a
		 * save file location.
		 */
		std::string _filePath;

		/** @brief Pointer to the user class
		 */
		os::smart_ptr<user> _user;
		/** @brief Pointer to public/private key pair
		 */
		os::smart_ptr<publicKey> _privateKey;
		/** @brief Pointer to the public key
		 */
		os::smart_ptr<number> _publicKey;

		/** @brief Public key algorithm ID
		 */
		uint16_t _prefferedPublicKeyAlgo;
		/** @brief Public key size (uint32_t size)
		 */
		uint16_t _prefferedPublicKeySize;
		/** @brief Hash algorithm ID
		 */
		uint16_t _prefferedHashAlgo;
		/** @brief Hash size (in bytes)
		 */
		uint16_t _prefferedHashSize;
		/** @brief Stream algorithm ID
		 */
		uint16_t _prefferedStreamAlgo;
	protected:
		/** @brief Triggered when the public key is changed
		 *
		 * Updates the gateway settings when the user indicates
		 * a public key has been updated.
		 *
		 * @param [in] pbk Updated public/private key pair
		 * @return void
		 */
		void publicKeyChanged(os::smart_ptr<publicKey> pbk);
	public:
		/** @brief Read/write mutex
		 *
		 * When this class is defined by a user, it is
		 * possible for the user to change the gateway
		 * settings during runtime.  Because of this,
		 * a read/write lock is required.
		 */
		os::readWriteLock lock;

		/** @brief User constructor
		 *
		 * Constructs the class from a user.  While this
		 * constructor can be called outside the user class,
		 * it is suggested to use the interface provided in
		 * crypto::user to create new gateway settings.
		 *
		 * @param [in] usr User defining the settings
		 * @param [in] groupID Group ID of the settings
		 * @param [in] filePath Save file location (optional)
		 */
		gatewaySettings(os::smart_ptr<user> usr, std::string groupID, std::string filePath="");
		/** @brief Ping message constructor
		 *
		 * Constructs the gateway settings from a ping message.
		 * This is usually used by the gateway to parse ping messages
		 * it receives.
		 *
		 * @param [in] msg Ping message
		 */
		gatewaySettings(const message& msg);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~gatewaySettings() throw();

		/** @brief Generate XML save stream
		 * @return XML save tree
		 */
		os::smart_ptr<os::XMLNode> generateSaveTree();
		/** @brief Ensure preferred algorithms are defined
		 *
		 * Uses current information in the class to determine
		 * if known algorithms define the preferred algorithms
		 * in this class.  If the preferred algorithms are not
		 * defined, they are changed to defined algorithms.
		 *
		 * @return void
		 */
		void update();
		/** @brief Saves the class to a file
		 * Saves the settings to an XML file,
		 * if the file path is defined.
		 * @return void
		 */
		void save();
		/** @brief Loads the class from a file
		 * Loads the settings from an XML file,
		 * if the file path is defined.
		 * @return void
		 */
		void load();

		/** @brief Return reference to the file path
		 * @return gatewaySettings::_filePath
		 */
		const std::string& filePath() const {return _filePath;}
		/** @brief Return reference to the group ID
		 * @return gatewaySettings::_groupID
		 */
		const std::string& groupID() const {return _groupID;}
		/** @brief Return reference to the node name
		 * @return gatewaySettings::_nodeName
		 */
		const std::string& nodeName() const {return _nodeName;}

		/** @brief Return user, if it is defined
		 * @return gatewaySettings::_user
		 */
		inline os::smart_ptr<user> getUser() {return _user;}
		/** @brief Return public/private key pair, if it is defined
		 * @return gatewaySettings::_privateKey
		 */
		inline os::smart_ptr<publicKey> getPrivateKey() {return _privateKey;}
		/** @brief Return public key
		 * @return gatewaySettings::_publicKey
		 */
		inline os::smart_ptr<number> getPublicKey() {return _publicKey;}

		/** @brief Return public key algorithm ID
		 * @return gatewaySettings::_prefferedPublicKeyAlgo
		 */
		inline uint16_t prefferedPublicKeyAlgo() const {return _prefferedPublicKeyAlgo;}
		/** @brief Return public key algorithm size
		 * @return gatewaySettings::_prefferedPublicKeySize
		 */
		inline uint16_t prefferedPublicKeySize() const {return _prefferedPublicKeySize;}
		/** @brief Return hash algorithm ID
		 * @return gatewaySettings::_prefferedHashAlgo
		 */
		inline uint16_t prefferedHashAlgo() const {return _prefferedHashAlgo;}
		/** @brief Return hash size
		 * @return gatewaySettings::_prefferedHashSize
		 */
		inline uint16_t prefferedHashSize() const {return _prefferedHashSize;}
		/** @brief Return stream algorithm ID
		 * @return gatewaySettings::_prefferedStreamAlgo
		 */
		inline uint16_t prefferedStreamAlgo() const {return _prefferedStreamAlgo;}

		/** @brief Construct a ping message
		 * @return New ping message
		 */
		os::smart_ptr<message> ping();

        /** @brief Cast nodeNameReference to size_t
         * @return Hashed location of nodeNameReference
         */
        inline operator size_t() const {return os::hashData(_groupID.c_str(),_groupID.length());}
        /** @brief Compare gatewaySettings by group ID
         * @return 0 if equal, 1 or -1 for greater than/less than
         */
        inline int compare(const gatewaySettings& cmp) const {return _groupID.compare(cmp._groupID);}

        #undef CURRENT_CLASS
        #define CURRENT_CLASS gatewaySettings
        COMPARE_OPERATORS
	};

	/** @brief Security gateway
	 *
	 * This gateway establishes a secured connection
	 * between two users.  The connection uses the
	 * preferred algorithms as defined by the user.
	 */
	class gateway: public errorSender
	{
	public:
		/** @brief Default timeout in seconds
		 */
		static const uint64_t DEFAULT_TIMEOUT=60;
		/** @brief Default error timeout in seconds
		 */
		static const uint64_t DEFAULT_ERROR_TIMEOUT=10;

		/** @brief Unknown state value
		 *
		 * This state is used by a gateway
		 * when the it is not aware of the
		 * current state of its reciprocal
		 * gateway.  A gateway should never be
		 * in this state itself.
		 */
		static const uint8_t UNKNOWN_STATE=0;
		/** @brief Unknown brother state
		 *
		 * A gateway is in this state when it
		 * is unaware of the gateway settings of
		 * its reciprocal, or brother, gateway.
		 * In short, a gateway which does not know
		 * its brother has not received a ping.
		 */
		static const uint8_t UNKNOWN_BROTHER=1;
		/** @brief Settings exchanged state
		 *
		 * Indicates that a gateway has received
		 * a ping message from its reciprocal gateway,
		 * but has not received notification that
		 * the reciprocal gateway has received the
		 * ping message from this gateway.
		 */
		static const uint8_t SETTINGS_EXCHANGED=2;
		/** @brief Establishing stream state
		 *
		 * In this state, a gateway sends a symmetric
		 * stream key encrypted with the public key
		 * of the brother gateway.
		 */
		static const uint8_t ESTABLISHING_STREAM=3;
		/** @brief Stream established state
		 *
		 * Gateways in this state continue to
		 * send the symmetric stream key, but
		 * also indicates to the brother gateway
		 * that the stream key sent by it has
		 * been received.
		 */
		static const uint8_t STREAM_ESTABLISHED=4;
		/** @brief Signing state
		 *
		 * Gateways in this state have established
		 * a secure stream with their brother node
		 * and now need to prove they have access
		 * to their declared public key.  The signing
		 * message also contains hashes of keys
		 * associated with the particular node.
		 */
		static const uint8_t SIGNING_STATE=5;
		/** @brief Confirm old key state
		 *
		 * This indicates that a gateway
		 * has authenticated the identity of
		 * it's brother but has not been
		 * notified that its identity has
		 * been authenticated.
		 */
		static const uint8_t CONFIRM_OLD=6;
		/** @brief Stream established state
		 *
		 * A secure and authentic stream
		 * has been established.  Messages
		 * can be passed securely through
		 * the gateway.
		 */
		static const uint8_t ESTABLISHED=7;

		/** @brief Confirm brother error state
		 *
		 * In this state, a gateway is acknowledging
		 * to it's brother that the error notification
		 * sent by the brother was received and logged.
		 */
		static const uint8_t CONFIRM_ERROR_STATE=252;
		/** @brief Basic error state
		 *
		 * A gateway has logged a low-level error.
		 * The connection must be re-set and
		 * re-established.
		 */
		static const uint8_t BASIC_ERROR_STATE=253;
		/** @brief Timeout error state
		 *
		 * Gateways are placed in this state when
		 * an error occurs while authenticating
		 * the connection.  Because an error in
		 * this state is usually both expensive
		 * and indicative of unauthorized access,
		 * when errors occur, this state forces
		 * a certain amount of time in the error
		 * state before allowing reconnection.
		 */
		static const uint8_t TIMEOUT_ERROR_STATE=254;
		/** @brief Permanent error state
		 *
		 * When gateways are in this state,
		 * a catastrophic error has occurred
		 * and the gateway refuses to reconnect.
		 */
		static const uint8_t PERMENANT_ERROR_STATE=255;
	private:
		/** @brief Settings of this gateway
		 *
		 * Defined by the user which constructed
		 * this gateway.
		 */
		os::smart_ptr<gatewaySettings> selfSettings;
		/** @brief Settings of the reciprocal gateway
		 *
		 * Defined by the ping message which
		 * is received by this gateway's
		 * brother gateway.
		 */
		os::smart_ptr<gatewaySettings> brotherSettings;
		/** @brief Mutex protected gateway states
		 */
		os::spinLock lock;
		/** @brief Mutex protecting timestamps
		 */
		os::spinLock stampLock;

		/** @brief Current state of this gateway
		 */
		uint8_t _currentState;
		/** @brief State of the reciprocal gateway
		 */
		uint8_t _brotherState;

		/** @brief Hold the most recent error
		 *
		 * This holds logging information
		 * for the most recent serious error.
		 * If an error is thrown while in an
		 * error state, the more serious
		 * error is kept in this variable.
		 */
		errorPointer _lastError;

		/** @brief Holds the level of the last error
		 *
		 * Either Basic, timeout or permanent.
		 * These are 253, 254 and 255 respectively.
		 */
		uint8_t _lastErrorLevel;
		/** @brief Time-stamp of the last error
		 */
		uint64_t _errorTimestamp;

		/** @brief Number of seconds till timeout
		 *
		 * This value is used when calculating timeout
		 * for receiving messages.
		 */
		uint64_t _timeout;
		/** @brief Number of seconds till partial timeout
		 *
		 * This value is used as the timeout value
		 * when sending messages and is less than
		 * the timeout value so that receiving is
		 * more permissive than sending.
		 */
		uint64_t _safeTimeout;
		/** @brief Number of seconds for error timeout
		 *
		 * When dealing with a timeout error, this
		 * defines how many seconds to wait before
		 * allowing a connection again.
		 */
		uint64_t _errorTimeout;
		/** @brief Time-stamp of last message received
		 */
		uint64_t _messageReceived;
		/** @brief Time-stamp of last message sent
		 */
		uint64_t _messageSent;

		//Public keys and algorithm definitions

		/** @brief Stream algorithm for this gateway
		 */
		os::smart_ptr<streamPackageFrame> selfStream;
		/** @brief Public key algorithm for this gateway
		 */
		os::smart_ptr<publicKeyPackageFrame> selfPKFrame;
		/** @brief Public/private key pair
		 */
		os::smart_ptr<publicKey> selfPublicKey;
		/** @brief Public key for this gateway
		 */
		os::smart_ptr<number> selfPreciseKey;

		/** @brief Stream algorithm for brother gateway
		 */
		os::smart_ptr<streamPackageFrame> brotherStream;
		/** @brief Public key algorithm for bro
		 */
		os::smart_ptr<publicKeyPackageFrame> brotherPKFrame;
		/** @brief Public key for brother gateway
		 */
		os::smart_ptr<number> brotherPublicKey;

		//Stream establishing

		/** @brief Stream defining message: in
		 *
		 * This is a record of the message
		 * which defined the incoming stream
		 * in-order to minimize public key
		 * cryptography performed.
		 */
		os::smart_ptr<message> streamMessageIn;
		/** @brief Stream for incoming messages
		 */
		os::smart_ptr<streamDecrypter> inputStream;

		/** @brief Time the output stream was defined
		 *
		 * Allows for redefinition of the output
		 * stream if the definition becomes stale.
		 */
		uint64_t streamEstTimestamp;
		/** @brief Stream defining message: out
		 *
		 * This is a record of the message
		 * which defined the outgoing stream
		 * in-order to minimize public key
		 * cryptography performed.
		 */
		os::smart_ptr<message> streamMessageOut;
		/** @brief Stream for outgoing messages
		 */
		os::smart_ptr<streamEncrypter> outputStream;

		//Signatures

		/** @brief Data for outgoing hashes
		 */
		os::smart_ptr<uint8_t> outputHashArray;
		/** @brief Length of outgoing hash array
		 */
		uint16_t outputHashLength;
		/** @brief Hash for primary signature
		 */
		os::smart_ptr<hash> selfPrimarySignatureHash;
		/** @brief Hash for historical signature
		 */
		os::smart_ptr<hash> selfSecondarySignatureHash;
		/** @brief Signing message: out
		 *
		 * This is a record of the message which
		 * was used to sign the current and
		 * historical public keys by this gateway
		 * in order to minimize the number of
		 * public key operations preformed.
		 */
		os::smart_ptr<message> selfSigningMessage;
		/** @brief List of eligible public keys
		 *
		 * This list of hashes comes from the
		 * brother of this gateway.  It is a
		 * list of the hashes of public keys
		 * associated with this node.
		 */
		os::pointerUnsortedList<hash> eligibleKeys;

		/** @brief Data for incoming hashes
		 */
		os::smart_ptr<uint8_t> inputHashArray;
		/** @brief Length of incoming hash array
		 */
		uint16_t inputHashLength;
		/** @brief Hash of brother's primary signature
		 *
		 * If this hash is defined, then this
		 * gateway's brother has properly signed
		 * with the public key it declared.
		 */
		os::smart_ptr<hash> brotherPrimarySignatureHash;
		/** @brief Hash of brother's historical signature
		 *
		 * When this hash is defined, this
		 * gateway's brother has properly signed
		 * with a historical public key.
		 */
		os::smart_ptr<hash> brotherSecondarySignatureHash;

		/** @brief Resets stream tracking
		 *
		 * Resets all pointers defined while
		 * establishing a secure stream.
		 *
		 * @return void
		 */
		void clearStream();
		/** @brief Builds the output stream
		 * @return void
		 */
		void buildStream();

		/** @brief Encrypt a message
		 *
		 * Uses the established output stream
		 * to encrypt the provided message
		 * and return it as a new message.
		 *
		 * @param [in] msg Message to be encrypted
		 * @return Encrypted message
		 */
		os::smart_ptr<message> encrypt(os::smart_ptr<message> msg);
		/** @brief Decrypt a message
		 *
		 * Uses the established input stream
		 * to decrypt the provided message
		 * and return it as a new message.
		 *
		 * @param [in] msg Message to be decrypted
		 * @return Decrypted message
		 */
		os::smart_ptr<message> decrypt(os::smart_ptr<message> msg);
		/** @brief Build current error message
		 * @return Message
		 */
		os::smart_ptr<message> currentError();
		/** @brief Reset error
		 *
		 * Resets all error variables and
		 * returns the gateway to its
		 * unconnected state.
		 *
		 * @return void
		 */
		void purgeLastError();

	protected:
		/** @brief Logs an error, with an error type
		 *
		 * Wraps the "logError" funciton as defined by
		 * the crypto::errorSender class, also sets this
		 * particular gateway into some error state.
		 *
		 * @param [in] elm Error description
		 * @param [in] errType Error level to determine timeout
		 *
		 * @return void
		 */
		void logError(errorPointer elm,uint8_t errType);
		/** @brief Logs an error, with type basic
		 *
		 * Sets this particular gateway into a default error
		 * state by calling "logError" with a type.
		 *
		 * @param [in] elm Eror description
		 * @return void
		 */
		void logError(errorPointer elm) {logError(elm,BASIC_ERROR_STATE);}
	public:
		/** @brief Gateway constructor
		 *
		 * Constructs a gateway from a user and
		 * a group ID.  This initializes all gateway
		 * variables and binds the user settings to this
		 * gateway.
		 *
		 * @param [in] usr User sending information through this gateway
		 * @param [in] groupID Defines group ID, "default" by default
		 */
		gateway(os::smart_ptr<user> usr,std::string groupID="default");
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~gateway()throw(){}

		/** @brief Return the node group of the brother
		 *
		 * Uses the current key bank to find the node
		 * associated with this brother.
		 *
		 * @return brother node
		 */
		os::smart_ptr<nodeGroup> brotherNode();
		/** @brief Returns next message from the gateway
		 *
		 * The function only returns the next message
		 * from the gateway's perspective.  Gateway
		 * management messages are returned by this
		 * function.
		 *
		 * @return Next management message
		 */
		os::smart_ptr<message> getMessage();
		/** @brief Send message through the gateway
		 *
		 * Takes a message and encrypts it with the
		 * gateway, assuming the secure stream has
		 * been established.  Returns an encrypted
		 * version of the message sent through the gateway.
		 *
		 * @param [in] msg Message to be encrypted
		 * @return Encrypted message
		 */
		os::smart_ptr<message> send(os::smart_ptr<message> msg);
		/** @brief Ping message
		 *
		 * Returns the ping message as defined
		 * by the gatewaySettings in this gateway.
		 *
		 * @return Ping message for this user
		 */
		os::smart_ptr<message> ping();
		/** @brief Process incoming message
		 *
		 * Decrypts and processes an incoming message.
		 * Note that messages must be coming from the
		 * brother gateway of this gateway.
		 *
		 * @param [in] msg Message to be processed
		 * @return Decrypted message
		 */
		os::smart_ptr<message> processMessage(os::smart_ptr<message> msg);
		/** @brief Cycle time-stamp data
		 *
		 * Compares registered time-stamps with the
		 * current time to determine if any state
		 * changes need to be made.
		 *
		 * @return void
		 */
		void processTimestamps();
		/** @brief Access brother settings
		 * @return Pointer to brother settings
		 */
		os::smart_ptr<gatewaySettings> getBrotherSettings() {return brotherSettings;}
		/** @brief Access self settings
		 * @return Pointer to self settings
		 */
		os::smart_ptr<gatewaySettings> getSelfSettings() {return selfSettings;}

		/** @brief This gateway's status
		 * @return gateway::_currentState
		 */
		inline uint8_t currentState() const {return _currentState;}
		/** @brief Brother gateway status
		 * @return gateway::_brotherState
		 */
		inline uint8_t brotherState() const {return _brotherState;}
		/** @brief Gateway security established
		 * @return true if established, else, false
		 */
		inline bool secure() const {return _currentState==ESTABLISHED;}

		/** @brief Current receiver-side timeout value
		 * @return gateway::_timeout
		 */
		inline uint64_t timeout() const {return _timeout;}
		/** @brief Current sender-side timeout value
		 * @return gateway::_safeTimeout
		 */
		inline uint64_t safeTimeout() const {return _safeTimeout;}
		/** @brief Current error timeout value
		 * @return gateway::_errorTimeout
		 */
		inline uint64_t errorTimeout() const {return _errorTimeout;}
		/** @brief Time-stamp of the last received message
		 * @return gateway::_messageReceived
		 */
		inline uint64_t timeMessageReceived() const {return _messageReceived;}
		/** @brief Time-stamp of the last sent message
		 * @return gateway::_messageSent
		 */
		inline uint64_t timeMessageSent() const {return _messageSent;}
		/** @brief Time-stamp of the last error
		 * @return gateway::_errorTimestamp
		 */
		inline uint64_t timeLastError() const {return _errorTimestamp;}
	};

}

#endif
