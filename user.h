/**
 * Provides a definition of user which
 * has a user-name, password and associated
 * bank of public keys.
 **/

#ifndef USER_H
#define USER_H

#include "binaryEncryption.h"
#include "cryptoLogging.h"
#include "cryptoError.h"
#include "keyBank.h"
#include "streamPackage.h"
#include "publicKeyPackage.h"
#include "gateway.h"

namespace crypto {

	/** @brief Primary user class
	 *
	 * The user class defines a set of keys
	 * associated with a local user.  This class
	 * notifies a set of listeners when various
	 * passwords and keys are changed, as this
	 * class allows for the encryption of a group
	 * of files with the provided keys
	 */
    class user: public os::savingGroup,public errorSender
	{
	protected:
		/** @breif Stores if the user was constructed
		 */
		bool _wasConstructed;
		/** @brief Name of user
		 */
		std::string _username;
		/** @brief Primary symmetric key
		 */
		unsigned char* _password;
		/** @brief Length of symmetric key
		 */
		size_t _passwordLength;
		/** @brief Save directory for user
		 */
		std::string _saveDir;

        /** @brief Default stream package
         */
        os::smart_ptr<streamPackageFrame> _streamPackage;
        /** @brief Key bank
		 *
		 * This key bank defines all of the public
		 * keys which are known by this user
		 */
		os::smart_ptr<keyBank> _keyBank;
		/** @brief Public keys
		 *
		 * This stores all public keys accociated with
		 * this specific user.
		 */
		os::pointerAVLTreeThreadSafe<publicKey> _publicKeys;
		/** @brief Default public key
		 *
		 * Sets the default public key definition.
		 * Note that a default public key will be
		 * defined the moment any public key
		 * is bound to a user.
		 */
		os::smart_ptr<publicKey> _defaultKey;
		/** @brief List of gateway settings
		 */
		os::pointerAVLTreeThreadSafe<gatewaySettings> _settings;

        /** @brief Creates meta-data XML file
         *
         * Constructs and returns the XML tree
         * for this class.  The XML tree may
         * or may not be encrypted.
         *
         * @return XML tree for saving
         */
        os::smart_ptr<os::XMLNode> generateSaveTree();
	public:
		/** @brief Returns the construction state of the user
		 * @return crypto::bool::_wasConstructed
		 */
		inline bool wasConstructed() const {return _wasConstructed;}
		/** @brief Constructs the user from scratch or directory
		 *
		 * Constructs a user from a directory or from scratch.
		 * If the specified directory does not exists, this
		 * class creates the directory and begins to populate
		 * it.  If no key is specified, all files are un-encrypted.
		 * If a key is specified, all files are encrypted with this
		 * key.
		 *
		 * @param [in] username Name of user to be saved
		 * @param [in] saveDir Directory to save users in
		 * @param [in] key Symetric key
		 * @param [in] keyLen Length of symetric key
		 *
		 */
		user(std::string username,std::string saveDir="",const unsigned char* key=NULL,size_t keyLen=0);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~user() throw();

		/** @brief Saves all dependencies
		 *
		 * This function saves all dependencies
		 * based on the save queue.
		 * @return void
		 */
		void save();

	//Set Data-----------------------------------------------------------

		/** @brief Set password
		 *
		 * Sets symetric key used to securely
		 * save user data.
		 *
		 * @param [in] key Symetric key
		 * @param [in] keyLen Length of symetric key
		 *
		 * @return void
		 */
		void setPassword(const unsigned char* key=NULL,size_t keyLen=0);
		/** @brief Set stream package
		 *
		 * Binds a new stream package.  Calls
		 * for saving of this user.
		 *
		 * @param [in] strmPack Stream package
		 *
		 * @return void
		 */
		void setStreamPackage(os::smart_ptr<streamPackageFrame> strmPack);
		/** @brief Sets the default public key
		 *
		 * Attempts to bind a public key as the
		 * default public key.  First checks if the
		 * key in question exists and binds the
		 * key with the characteristics of the
		 * provided key as the default key.
		 *
		 * @param [in] key Public key to be bound as the default key
		 * @return True if default key bound, else, false
		 */
		bool setDefaultPublicKey(os::smart_ptr<publicKey> key);
		/** @brief Attempt to add new public key
		 *
		 * Attempts to add a public key to the
		 * public key bank.  If successful, and
		 * if the default key is NULL, the added
		 * key becomes the default key.
		 *
		 * @param [in] key Public key to be added
		 * @return True if successfully added, else, false
		 */
		bool addPublicKey(os::smart_ptr<publicKey> key);
		/** @brief Find public key by information
		 *
		 * Searches for a public key with the given'
		 * characteristics.  Keys are searched by
		 * algorithm and size.
		 *
		 * @param [in] pkfrm Public key information to match
		 * @return Public key matching intrinsics
		 */
		os::smart_ptr<publicKey> findPublicKey(os::smart_ptr<publicKeyPackageFrame> pkfrm);

	//Raw Message Passing------------------------------------------------

		/** @brief Check if a message is an ID message
		 *
		 * Checks the first byte of a message to see if it
		 * is an ID message.
		 *
		 * @return True if an ID message, else, false
		 */
		static bool isIDMessage(unsigned char m){return (0x0F & m)==0;}
		/** @brief Check if a message is a data message
		 *
		 * Checks the first byte of a message to see if it
		 * is a data message.
		 *
		 * @return True if a data message, else, false
		 */
		static bool isDataMessage(unsigned char m){return (0x0F & m)==1;}
		/** @brief Check if a message is encrypted
		 *
		 * Checks the first byte of a message to see if it
		 * is encrypted
		 *
		 * @return True if encrypted, else, false
		 */
		static bool isEncrypted(unsigned char m){return (0x80 & m);}
		/** @brief Produces an unsigned ID message
		 *
		 * Generates an identification message to be sent to
		 * a node.  If the target node is specified, this
		 * function will encrypt the target message for
		 * that target node.
		 *
		 * @param [out] len Length of returned array
		 * @param [in] groupID Group this user is part of
		 * @param [in] nodeName Name of target node
		 * @return Unsigned ID message
		 */
		unsigned char* unsignedIDMessage(size_t& len, std::string groupID="default",std::string nodeName="");
		/** @brief Process ID message
		 *
		 * Processes any ID message.  Note that this function can process
		 * both targeted and non-targeted ID messages.
		 *
		 * @param [in] mess Incoming message
		 * @param [in] len Length of incoming message
		 * @return True if valid ID message, else, false
		 */
		bool processIDMessage(unsigned char* mess, size_t len);
		/** @brief Encrypt an out-going message
		 *
		 * Takes an array of data and encrypts it with the
		 * default public-key of the target user.  Takes a group
		 * ID and node name to target the message.
		 *
		 * @param [out] finishedLen Length of the finished message
		 * @param [in] mess Message to be encrypted
		 * @param [in] len Length of message to be encrypted
		 * @param [in] groupID String of the target group
		 * @param [in] nodeName String of the name of the target node
		 * @return Encrypted message pointer
		 */
		unsigned char* encryptMessage(size_t& finishedLen, const unsigned char* mess, size_t len, std::string groupID,std::string nodeName);
		/** @brief Decrypt a message
		 *
		 * Takes an array of data representing an encrypted message targeted for this user.
		 * The message is decrypted and returned.
		 *
		 * @param [out] finishedLen Length of the finished message
		 * @param [in] mess Message to be decrypted
		 * @param [in] len Length of the message to be decrypted
		 * @param [in] groupID Group ID of message source
		 * @param [in] nodeName Name of message source
		 * @return Decrypted message
		 */
		unsigned char* decryptMessage(size_t& finishedLen, const unsigned char* mess, size_t len, std::string groupID,std::string nodeName);

	//Access-------------------------------------------------------------

		/** @brief Access name of user
		 * @return crypto::user::_username
		 */
		const std::string& username() const {return _username;}
		/** @brief Access raw password
		 * @return crypto::user::_password
		 */
		const unsigned char* password() const {return _password;}
		/** @brief Access password length
		 * @return crypto::user::_passwordLength
		 */
		size_t passwordLength() const {return _passwordLength;}
		/** @brief Access save directory
		 * @return crypto::user::_saveDir + username
		 */
		std::string directory() const {return _saveDir+"/"+_username;}
		/** @brief Access streaming package
		 * @return crypto::user::_streamPackage
		 */
		os::smart_ptr<streamPackageFrame> streamPackage() const {return _streamPackage;}
		/** @brief Access key bank
		 * @return crypto::user::_keyBank
		 */
		os::smart_ptr<keyBank> getKeyBank() {return _keyBank;}
		/** @brief Returns the default public key
		 * @return crypto::user::_defaultKey
		 */
		os::smart_ptr<publicKey> getDefaultPublicKey() {return _defaultKey;}

		/** @brief Returns the first public key group
		 *
		 * Allows programs to list off the available
		 * key groups bound to this user
		 *
		 * @return crypto::user::_publicKeys.getFirst()
		 */
		os::iterator<publicKey> getFirstPublicKey() {return _publicKeys.first();}
		/** @brief Returns the last public key group
		 *
		 * Allows programs to list off the available
		 * key groups bound to this user
		 *
		 * @return crypto::user::_publicKeys.getFirst()
		 */
		os::iterator<publicKey> getLastPublicKey() {return _publicKeys.last();}

		/** @brief Find gateway settings
		 * @param [in] group Name of group of the settings
		 * @return Pointer to the found gateway settings
		 */
		os::smart_ptr<gatewaySettings> findSettings(std::string group="default");
		/** @brief Insert gateway settings
		 * @param [in] group Name of group of the settings
		 * @return Point to the inserted gateway settings
		 */
		os::smart_ptr<gatewaySettings> insertSettings(std::string group);

		/** @brief Returns the first gateway settings group
		 *
		 * Allows programs to list off the available
		 * gateway settings bound to this user
		 *
		 * @return crypto::user::_settings.getFirst()
		 */
        os::iterator<gatewaySettings> getFirstSettings() {return _settings.first();}
		/** @brief Returns the last gateway settings group
		 *
		 * Allows programs to list off the available
		 * gateway settings bound to this user
		 *
		 * @return crypto::user::_settings.getLast()
		 */
		os::iterator<gatewaySettings> getLastSettings() {return _settings.last();}

		/** @brief Searches for key by hash
		 *
		 * Binds the location that the keys were found
		 * in to the arguments of the function.
		 *
		 * @param [in] hsh Hash of the key to be searched for
		 * @param [out] hist History value the key was found
		 * @param [out] type Type (public or private)
		 * @return Key pair conatining the searched key
		 */
		os::smart_ptr<publicKey> searchKey(hash hsh, size_t& hist,bool& type);
		/** @brief Searches for key
		 *
		 * Binds the location that the keys were found
		 * in to the arguments of the function.
		 *
		 * @param [in] num Key to search for
		 * @param [out] hist History value the key was found
		 * @param [out] type Type (public or private)
		 * @return Key pair conatining the searched key
		 */
		os::smart_ptr<publicKey> searchKey(os::smart_ptr<number> key, size_t& hist,bool& type);
		/** @brief Searches for key
		 * @param [in] num Key to search for
		 * @return Key pair conatining the searched key
		 */
		os::smart_ptr<publicKey> searchKey(hash hsh)
		{
			size_t hist;
			bool type;
			return searchKey(hsh,hist,type);
		}
		/** @brief Searches for key
		 * @param [in] num Key to search for
		 * @return Key pair conatining the searched key
		 */
		os::smart_ptr<publicKey> searchKey(os::smart_ptr<number> key)
		{
			size_t hist;
			bool type;
			return searchKey(key,hist,type);
		}
	};
}

#endif
