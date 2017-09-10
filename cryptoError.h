/**
 * Declares a number of errors for
 * the CryptoGateway package.  Also
 * declares two classes to manage
 * the sending and listening for the
 * throwing of crypto::errorPointer.
 **/

#ifndef CRYPTO_ERROR_H
#define CRYPTO_ERROR_H

#include "streamPackage.h"
#include "cryptoLogging.h"
#include "osMechanics/osMechanics.h"

namespace crypto {

	/** @brief Sortable exception
	 *
	 * This class allows for more
	 * sophisticated logging of errors.
	 * It contains the time which the error
	 * occurred and can be thrown.
	 */
    class error: public std::exception
	{
		/** @brief Time the error was created
		 */
		uint64_t _timestamp;
		/** @brief Full error output
		 *
		 * The crypto::error::what() function
		 * must return a C string.  This string
		 * is the position in memory that function
		 * returns.  crypto::error::what() also
		 * constructs this string.
		 */
		std::string whatString;
	public:
		/** @brief Error constructor
		 *
		 * Constructs an error by setting
		 * the timestamp to the current time.
		 */
		error(){_timestamp=os::getTimestamp();}
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~error() throw() {}

		/** @brief Short error descriptor
		 * Returns "Error"
		 * @return Error title std::string
		 */
		inline virtual std::string errorTitle() const {return "Error";}
		/** @brief Long error descriptor
		 * Returns "No description"
		 * @return Error description std::string
		 */
		inline virtual std::string errorDescription() const {return "No description";}
		/** @brief Timestamp converted to string
		 * Returns the timestamp in a human
		 * readable string.
		 * @return Time error was created
		 */
		std::string timestampString() const {return os::convertTimestamp(_timestamp);}
		/** @brief Logs error to crypto::cryptoerr
		 * Logs the error title, time created and error
		 * description on the CryptoGateway error log.
		 * @return void
		 */
		void log() const {cryptoerr<<errorTitle()<<" on "<<timestampString()<<" : "<<errorDescription()<<std::endl;}

		/** @brief Time created
		 * @return crypto::error::_timestamp
		 */
		uint64_t timestamp() const {return _timestamp;}
		/** @brief Concatenated error data
		 * Returns a C string of the error
		 * title, time constructed and error
		 * description.
		 * @return Character pointer to error data
		 */
		const char* what() const throw()
		{
			error* e=(error*) this;	//Bad practice, but the nature of this class makes this needed
			e->whatString=errorTitle()+" on "+timestampString()+" : "+errorDescription();
			return whatString.c_str();
		}

        #undef CURRENT_CLASS
        #define CURRENT_CLASS error
        POINTER_HASH_CAST
        POINTER_COMPARE
        COMPARE_OPERATORS
	};
	/** @brief Smart pointer to crypto::error
	 */
	typedef os::smart_ptr<error> errorPointer;

	/** @brief Symmetric key too small
	 *
	 * Thrown when a symmetric key is
	 * provided which is smaller than
	 * the minimum for the specific algorithm.
	 */
	class passwordSmallError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~passwordSmallError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Password Size Error"
		 * @return Error title std::string
		 */
		inline std::string errorTitle() const {return "Password Size Error";}
		/** @brief Long error descriptor
		 * Returns "Password too small"
		 * @return Error description std::string
		 */
		inline std::string errorDescription() const {return "Password too small";}
	};
	/** @brief Symmetric key too big
	 *
	 * Thrown when a symmetric key is
	 * provided which is bigger than
	 * the maximum for the specific algorithm.
	 */
	class passwordLargeError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~passwordLargeError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Password Size Error"
		 * @return Error title std::string
		 */
		inline std::string errorTitle() const {return "Password Size Error";}
		/** @brief Long error descriptor
		 * Returns "Password too large"
		 * @return Error description std::string
		 */
		inline std::string errorDescription() const {return "Password too large";}
	};

	/** @brief Buffer too small
	 *
	 * Thrown when the buffer provided
	 * to some cryptographic function
	 * is too small.
	 */
	class bufferSmallError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~bufferSmallError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Buffer Size Error"
		 * @return Error title std::string
		 */
		inline std::string errorTitle() const {return "Buffer Size Error";}
		/** @brief Long error descriptor
		 * Returns "Buffer too small"
		 * @return Error description std::string
		 */
		inline std::string errorDescription() const {return "Buffer too small";}
	};
	/** @brief Buffer too large
	 *
	 * Thrown when the buffer provided
	 * to some cryptographic function
	 * is too large.
	 */
	class bufferLargeError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~bufferLargeError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Buffer Size Error"
		 * @return Error title std::string
		 */
		inline std::string errorTitle() const {return "Buffer Size Error";}
		/** @brief Long error descriptor
		 * Returns "Buffer too large"
		 * @return Error description std::string
		 */
		inline std::string errorDescription() const {return "Buffer too large";}
	};
	/** @brief ADS Insertion Failed
	 *
	 * Thrown when insertion to an
	 * os::ads structure unexpectedly
	 * fails.
	 */
	class insertionFailed: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~insertionFailed() throw() {}
		/** @brief Short error descriptor
		 * Returns "Insertion Failed"
		 * @return Error title std::string
		 */
		inline std::string errorTitle() const {return "Insertion Failed";}
		/** @brief Long error descriptor
		 * Returns "Insertion into an abstract
		 * data-structure unexpectedly failed"
		 * @return Error description std::string
		 */
		inline std::string errorDescription() const {return "Insertion into an abstract data-structure unexpectedly failed";}
	};

	/** @brief Custom crypto::error
	 *
	 * Allows the programmer to define
	 * an error unique to a specific
	 * situation.
	 */
	class customError: public error
	{
		/** @ Short error descriptor
		 */
		std::string _name;
		/** @ Long error descriptor
		 */
		std::string _description;
	public:
		/** @brief Custom error constructor
		 * @param [in] name Short error tag
		 * @param [in] description Long error description
		 */
		customError(std::string name, std::string description)
		{
			_name=name;
			_description=description;
		}
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~customError() throw() {}
		/** @brief Short error descriptor
		 * Returns "<name>" (crypto::customError::_name)
		 * @return Error title std::string
		 */
		inline std::string errorTitle() const {return _name;}
		/** @brief Long error descriptor
		 * Returns "<description>" (crypto::customError::_description)
		 * @return Error description std::string
		 */
		inline std::string errorDescription() const {return _description;}
	};

	/** @brief File open error
	 *
	 * Thrown when a file cannot be
	 * found in the specified location.
	 */
	class fileOpenError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~fileOpenError() throw() {}
		/** @brief Short error descriptor
		 * Returns "File Open Error"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "File Open Error";}
		/** @brief Long error descriptor
		 * Returns "Cannot open the specified file"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Cannot open the specified file";}
	};
	/** @brief File format error
	 *
	 * Thrown when a file is parsed
	 * but an error occurs while parsing.
	 */
	class fileFormatError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~fileFormatError() throw() {}
		/** @brief Short error descriptor
		 * Returns "File Format Error"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "File Format Error";}
		/** @brief Long error descriptor
		 * Returns "The file is not of the
		 * specified format, and an error resulted"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "The file is not of the specified format, and an error resulted";}
	};
	/** @brief Algorithm bound failure
	 *
	 * Thrown when an algorithm cannot
	 * be found or used.  Usually indicates
	 * the specified algorithm is not
	 * defined by the active version.
	 */
	class illegalAlgorithmBind: public error
	{
		/** @brief Name of algorithm
		 */
		std::string algorithmName;
	public:
		/** @brief Illegal algorithm error
		 *
		 * @param [in] algoName Name of illegal algorithm
		 */
		illegalAlgorithmBind(std::string algoName){algorithmName=algoName;}
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~illegalAlgorithmBind() throw() {}
		/** @brief Short error descriptor
		 * Returns "Illegal Algorithm Bind"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Illegal Algorithm Bind";}
		/** @brief Long error descriptor
		 * Returns "Cannot bind algorithm of type: <algorithmName>"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Cannot bind algorithm of type: "+algorithmName;}
	};
	/** @brief Hash mis-match
	 *
	 * Thrown when two hashes do
	 * not match.  This error can
	 * be indicative of larger security
	 * issues, as it most commonly
	 * occurs during a failed authentication.
	 */
	class hashCompareError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~hashCompareError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Hash Compare"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Hash Compare";}
		/** @brief Long error descriptor
		 * Returns "Provided and calculated hashes do not match"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Provided and calculated hashes do not match";}
	};
	/** @brief Hash generation error
	 *
	 * Thrown when a hash encounters
	 * an error while being created.
	 */
	class hashGenerationError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~hashGenerationError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Hash Generation"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Hash Generation";}
		/** @brief Long error descriptor
		 * Returns "Could not generate
		 * a hash with the given arguments"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Could not generate a hash with the given arguments";}
	};

	/** @brief File error
	 *
	 * Thrown when an action
	 * is attempted on a file
	 * in the error state.
	 */
	class actionOnFileError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~actionOnFileError() throw() {}
		/** @brief Short error descriptor
		 * Returns "Action on File Error"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Action on File Error";}
		/** @brief Long error descriptor
		 * Returns "Cannot preform action
		 * on a file in the error state"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Cannot preform action on a file in the error state";}
	};
	/** @brief File closed error
	 *
	 * Thrown when an action
	 * is attempted on a file
	 * which is already closed.
	 */
	class actionOnFileClosed: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~actionOnFileClosed() throw() {}
		/** @brief Short error descriptor
		 * Returns "Action on File Closed"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Action on File Closed";}
		/** @brief Long error descriptor
		 * Returns "Cannot preform action
		 * on a file in the closed state"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Cannot preform action on a file in the closed state";}
	};

	/** @brief Public-key size error
	 *
	 * Thrown when a public key or
	 * public key interaction detects
	 * a size mis-match or illegal
	 * size.
	 */
	class publicKeySizeWrong: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~publicKeySizeWrong() throw() {}
		/** @brief Short error descriptor
		 * Returns "Public Key Size Wrong"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Public Key Size Wrong";}
		/** @brief Long error descriptor
		 * Returns "Attempted to use a
		 * code or n of improper size"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Attempted to use a code or n of improper size";}
	};
	/** @brief Key missing error
	 *
	 * Thrown when a key cannot
	 * be found to decrypt the
	 * incoming data stream
	 */
	class keyMissing: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~keyMissing() throw() {}
		/** @brief Short error descriptor
		 * Returns "Key missing"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Key missing";}
		/** @brief Long error descriptor
		 * Returns "Cannot decrypt the
		 * data stream, the key is missing!"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Cannot decrypt the data stream, the key is missing!";}
	};
	/** @brief NULL public-key error
	 *
	 * Thrown when a NULL public-key
	 * or public-key of undefined type is
	 * used.
	 */
	class NULLPublicKey: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~NULLPublicKey() throw() {}
		/** @brief Short error descriptor
		 * Returns "Public Key NULL"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Public Key NULL";}
		/** @brief Long error descriptor
		 * Returns "Attempted to bind a
		 * public key of illegal type NULL"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Attempted to bind a public key of illegal type NULL";}
	};
	/** @brief NULL data error
	 *
	 * Thrown when NULL data is
	 * passed to a function or class.
	 */
	class NULLDataError: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~NULLDataError() throw() {}
		/** @brief Short error descriptor
		 * Returns "NULL Data"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "NULL Data";}
		/** @brief Long error descriptor
		 * Returns "A function was passed
		 * NULL data where this is illegal"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "A function was passed NULL data where this is illegal";}
	};
	/** @brief NULL master error
	 *
	 * Thrown when a class is
	 * passed a NULL master where
	 * such a class must have a
	 * defined master.
	 */
	class NULLMaster: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~NULLMaster() throw() {}
		/** @brief Short error descriptor
		 * Returns "NULL Master pointer"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "NULL Master pointer";}
		/** @brief Long error descriptor
		 * Returns "A class received a
		 * NULL master pointer, this is illegal"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "A class received a NULL master pointer, this is illegal";}
	};
	/** @brief Master mis-match
	 *
	 * Thrown when two elements
	 * attempt an interaction but
	 * have different masters.
	 */
	class masterMismatch: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~masterMismatch() throw() {}
		/** @brief Short error descriptor
		 * Returns "Master Comparison Mis-match"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Master Comparison Mis-match";}
		/** @brief Long error descriptor
		 * Returns "Two nodes which are
		 * interacting have different masters!"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Two nodes which are interacting have different masters!";}
	};
	/** @brief Unknown error
	 *
	 * Thrown when an error of
	 * undefined type occurs.  Used
	 * as a catch-all exception.
	 */
	class unknownErrorType: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~unknownErrorType() throw() {}
		/** @brief Short error descriptor
		 * Returns "Unknown Error Type"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Unknown Error Type";}
		/** @brief Long error descriptor
		 * Returns "Caught some exception,
		 * but the type is unknown"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Caught some exception, but the type is unknown";}
	};

	/** @brief String size error
	 *
	 * Thrown when either the username or
	 * group ID are too large.
	 */
	class stringTooLarge: public error
	{
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.  Must explicitly declare that
         * this function does not throw exceptions.
         */
		virtual ~stringTooLarge() throw() {}
		/** @brief Short error descriptor
		 * Returns "Group ID/Name Size Error"
		 * @return Error title std::string
		 */
		std::string errorTitle() const {return "Group ID/Name Size Error";}
		/** @brief Long error descriptor
		 * Returns "Group ID or Name was
		 * larger than the maximum size.
		 * Please user a smaller string"
		 * @return Error description std::string
		 */
		std::string errorDescription() const {return "Group ID or Name was larger than the maximum size.  Please user a smaller string";}
	};

	///@cond INTERNAL
	class errorSender;
	///@endcond

	/** @brief crypto::error listener
	 *
	 * Defines a class which is notified
	 * when another class throws a crypto::error.
	 */
	class errorListener
	{
	private:
		/** @brief Friendship with crypto::errorSender
		 *
		 * The error sender must be able
		 * to add and remove itself
		 * from the listener's set.
		 */
		friend class errorSender;
		/** @brief Set protection mutex
		 *
		 * Protects access to the
		 * set of senders, allows
		 * for multi-threading.
		 */
		os::spinLock mtx;
		/** @brief Set of senders
		 *
		 * All of the senders this
		 * listener is registered
		 * to.
		 */
		os::pointerSet<errorSender> senders;
	public:
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~errorListener() throw();

		/** @brief Receive error event
		 *
		 * Receives error from one of
		 * the senders this listener is
		 * registered to.
		 *
		 * @param [in] elm Error sent
		 * @param [in] source Sender which sent error
		 * @return void
		 */
		virtual void receiveError(errorPointer elm,os::smart_ptr<errorSender> source){}

        #undef CURRENT_CLASS
        #define CURRENT_CLASS errorListener
        POINTER_HASH_CAST
        POINTER_COMPARE
        COMPARE_OPERATORS
	};

	/** @brief Sends crypto::error
	 *
	 * Sends and logs crypto:error
	 * pointers.  Does not catch
	 * the errors, simply logs ones
	 * which have already been created
	 * and caught.
	 */
	class errorSender
	{
		/** @brief Friendship with crypto::errorListener
		 *
		 * The error listener must be able
		 * to add and remove itself
		 * from the sender's set.
		 */
		friend class errorListener;
		/** @brief Set protection mutex
		 *
		 * Protects access to the
		 * set of listeners, allows
		 * for multi-threading.
		 */
		os::spinLock listenerLock; //Shouldn't need
		/** @brief Set of listeners
		 *
		 * All of the listeners registered
		 * to this sender.
		 */
		os::pointerSet<errorListener> errorListen;

		/** @brief List of current errors
		 */
		os::pointerUnsortedList<error> errorLog;
		/** @brief Number of errors kept
		 *
		 * Allows for old errors to expire
		 * in the event a sender logs
		 * a lot of errors.
		 */
		unsigned int _logLength;
	protected:
		/** @brief Logs an error
		 * Dispatches an event to all
		 * listeners and stores the
		 * error in the log.
		 *
		 * @param [in] elm Error to be logged
		 * @return void
		 */
		virtual void logError(errorPointer elm);
	public:
		/** @brief Error sender constructor
		 *
		 * Sets the length of the log
		 * to 20.  Initializes with no
		 * errors and no listeners
		 */
		errorSender(){_logLength=20;}
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
		virtual ~errorSender() throw();

		/** @brief Register listener
		 * @param [in/out] listener Listener to register
		 * @return void
		 */
		void pushErrorListener(os::smart_ptr<errorListener> listener);
		/** @brief Un-register listener
		 * @param [in] listener Listener to un-register
		 * @return void
		 */
		void removeErrrorListener(os::smart_ptr<errorListener> listener);

		/** @brief Removes error from log
		 * @return Oldest recorded error
		 */
		errorPointer popError();

		/** @brief Set length of log
		 * @param [in] logLength Target length of log
		 * @return void
		 */
		void setLogLength(unsigned int logLength);
		/** @brief Return length of log
		 * @return crypto::errorSender::_logLength
		 */
		size_t logLength() const {return _logLength;}
		/** @brief Return number of errors in log
		 * @return crypto::errorSender::errorLog.size()
		 */
		size_t numberErrors() const {return errorLog.size();}

        #undef CURRENT_CLASS
        #define CURRENT_CLASS errorSender
        POINTER_HASH_CAST
        POINTER_COMPARE
        COMPARE_OPERATORS
	};
};

#endif
