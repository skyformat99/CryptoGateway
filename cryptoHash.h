/**
 * Declares base cryptographic hashing
 * class and functions.  All hash algorithms
 * should extend this hash class.
 **/

#ifndef CRYPTO_HASH_H
#define CRYPTO_HASH_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "Datastructures/Datastructures.h"
#include "hexConversion.h"
#include "cryptoConstants.h"

namespace crypto {

    ///@cond INTERNAL
    class hash;
    ///@endcond

    /** @brief Output stream operator
     *
     * Outputs a hex version of the hash
     * to the provided output stream.  This
     * output will look identical for two
     * hashes which are equal but have different
     * algorithms.
     *
     * @param [in/out] os Output stream
     * @param [in] num Hash to be printed
     * return Reference to output stream
     */
    std::ostream& operator<<(std::ostream& os, const hash& num);
    /** @brief Input stream operator
     *
     * Inputs a hex version of the hash
     * from the provided output stream.
     * This function must receive a constructed
     * hash, although it will rebuild the
     * provided hash with the stream data.
     *
     * @param [in/out] is Input stream
     * @param [in] num Hash to be created
     * return Reference to input stream
     */
    std::istream& operator>>(std::istream& is, hash& num);

    /** @brief Base hash class
     *
     * This class manages the raw
     * data of all hashes.  Subsequent
     * hashes define different algorithms
     * to populate the hashes.
     */
    class hash
    {
        /** @brief Hash algorithm ID
         */
        uint16_t _algorithm;
    protected:
        /** @brief Number of bytes in the hash
         */
        uint16_t _size;
        /** @brief Raw hash data
         */
        unsigned char* _data;

        /** @brief Default hash constructor
         *
         * Constructs a hash with the given size and
         * algorithm ID, initializing the entire hash
         * itself to 0.
         *
         * @param [in] algorithm Algorithm ID, NULL by default
         * @param [in] size Size of hash, crypto::size::defaultHash by default
         */
        hash(uint16_t algorithm=algo::hashNULL,uint16_t size=size::defaultHash);
    public:
        /** @brief Algorithm name string access
         *
         * Returns the name of the current
         * algorithm string.  This function
         * is static and can be accessed without
         * instantiating the class.
         *
         * @return "NULL"
         */
        inline static std::string staticAlgorithmName() {return "NULL";}
        /** @brief Algorithm ID number access
         *
         * Returns the ID of the current
         * algorithm.  This function
         * is static and can be accessed without
         * instantiating the class.
         *
         * @return crypto::algo::hashNULL
         */
        inline static uint16_t staticAlgorithm() {return algo::hashNULL;}

        /** @brief Hash copy constructor
         *
         * Constructs a hash with a hash.  This
         * copy constructor re-initializes the
         * data array for the new hash.
         *
         * @param [in] cpy Hash to copy
         */
        hash(const hash& cpy);
        /** @brief Equality constructor
         *
         * Rebuild this hash with the data
         * from another hash.
         *
         * @param [in] cpy Hash to copy
         * @return Reference to this
         */
        hash& operator=(const hash& cpy);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~hash();
        /** @brief Comparison function
         *
         * Takes into consideration the algorithm,
         * size of the data and content of the hash.
         * Used for all of the equality operators.
         *
         * @return 0 if equal, 1 if greater than, -1 if less than
         */
        int compare(const hash* _comp) const;

        /** @brief Binds a data-set
         *
         * Preforms the hash algorithm on the
         * set of data provided and binds the
         * result to this hash.
         *
         * @param [in] data Data array to be hashed
         * @param [in] dLen Length of data array
         */
        virtual void preformHash(unsigned char* data, size_t dLen){}

        /** @brief Algorithm name string access
         *
         * Returns the name of the current
         * algorithm string.  This function
         * is virtual, so changes for each
         * hash algorithm
         *
         * @return "NULL"
         */
        inline virtual std::string algorithmName() const {return hash::staticAlgorithmName();}
        /** @brief Current algorithm ID
         *
         * Returns the algorithm ID bound
         * to this hash.
         *
         * @return crypto::hash::_algorithm
         */
        inline uint16_t algorithm() const {return _algorithm;}
        /** @brief Current hash size
         *
         * Returns the hash size bound
         * to this hash in bytes.
         *
         * @return crypto::hash::_size
         */
        inline uint16_t size() const {return _size;}
        /** @brief Current hash size, bits
         *
         * Return the hash size bound
         * to this hash in bits.
         *
         * @return crypto::hash::_size*8
         */
        inline size_t numBits() const {return _size*8;}
        /** @brief Modifiable data access
         *
         * Provides mutable data-access to
         * the raw hash data.
         *
         * @return crypto::hash::_data
         */
        inline unsigned char* data() {return _data;}
        /** @brief Constant data access
         *
         * Provides immutable data-access to
         * the raw hash data.
         *
         * @return crypto::hash::_data
         */
        inline const unsigned char* data() const {return _data;}

        /** @brief Modifiable data access
         *
         * Provides mutable data-access to
         * the raw hash data.
         *
         * @param [in] pos Data index
         * @return crypto::hash::_data[pos]
         */
        unsigned char operator[](size_t pos) const;
        /** @brief Constant data access
         *
         * Provides immutable data-access to
         * the raw hash data.
         *
         * @param [in] pos Data index
         * @return crypto::hash::_data[pos]
         */
        unsigned char& operator[](size_t pos);

        /** @brief Converts hash to string
         *
         * Converts the hash to a hex
         * string.
         *
         * @return String representation of the hash
         */
        std::string toString() const;
        /** @brief Converts from string
         *
         * Rebuilds the hash from a hex
         * string.
         *
         * @param [in] str Hex string
         * @return String representation of the hash
         */
        void fromString(const std::string& str);

        //Comparison functions
        bool operator==(const hash& comp) const{return compare(&comp)==0;}
        bool operator!=(const hash& comp) const{return compare(&comp)!=0;}
        bool operator>(const hash& comp) const{return compare(&comp)==1;}
        bool operator>=(const hash& comp) const{return compare(&comp)>=0;}
        bool operator<(const hash& comp) const{return compare(&comp)==-1;}
        bool operator<=(const hash& comp) const{return compare(&comp)<=0;}

        /** @brief Cast to a size_t for hashing
         * ALlows data structures to cast this
         * object to a size_t for hash tables.
         * @return void
         */
        inline operator size_t() const {return os::hashData(_data, _size);}
    };

    /** @brief Hashes data with the specified algorithm
     *
     * Hashes the provided data array returning
     * a hash of the specified algorithm.  This is a
     * template function, which calls the static
     * hash function for the specified algorithm.
     *
     * @param [in] hashType Size of hash
     * @param [in] data Data array to be hashed
     * @param [in] length Length of data to be hashed
     * @return Hash for data array
     */
    template <class hashClass>
    hashClass hashData(uint16_t hashType,const unsigned char* data, size_t length)
    {
        if(hashType==size::hash64)
            return hashClass::hash64Bit(data,length);
        else if(hashType==size::hash128)
            return hashClass::hash128Bit(data,length);
        else if(hashType==size::hash256)
            return hashClass::hash256Bit(data,length);
        else if(hashType==size::hash512)
            return hashClass::hash512Bit(data,length);
        return hashClass::hash256Bit(data,length);
    }


    /** @brief XOR hash class
     *
     * This class defines an XOR
     * based hash.  Note that this
     * hash is not cryptographically
     * secure and essentially just acts
     * as a checksum.
     */
    class xorHash:public hash
    {
    private:
        /** @brief XOR hash constructor
         *
         * Constructs a hash with the data to
         * be hashed, the length of the array
         * and the size of the hash to be constructed.
         *
         * @param [in] data Data array
         * @param [in] length Length of data array
         * @param [in] size Size of hash
         */
        xorHash(const unsigned char* data, size_t length, uint16_t size);
    public:
        /** @brief Algorithm name string access
         *
         * Returns the name of the current
         * algorithm string.  This function
         * is static and can be accessed without
         * instantiating the class.
         *
         * @return "XOR"
         */
        inline static std::string staticAlgorithmName() {return "XOR";}
        /** @brief Algorithm ID number access
         *
         * Returns the ID of the current
         * algorithm.  This function
         * is static and can be accessed without
         * instantiating the class.
         *
         * @return crypto::algo::hashXOR
         */
        inline static uint16_t staticAlgorithm() {return algo::hashXOR;}

        /** @brief Default XOR hash constructor
         *
         * Constructs an empty XOR hash
         * class.
         */
        xorHash():hash(xorHash::staticAlgorithm()){}
        /** @brief Raw data copy
         *
         * Initializes the XOR hash
         * with a data array.  This
         * data array is not hashed
         * but assumed to represent
         * hashed data.
         *
         * @param [in] data Hashed data array
         * @param [in] size Size of hash array
         */
        xorHash(const unsigned char* data, uint16_t size);
        /** @brief XOR copy constructor
         *
         * Constructs an XOR hash with
         * another XOR hash.
         *
         * @param [in] cpy Hash to be copied
         */
        xorHash(const xorHash& cpy):hash(cpy){}
        /** @brief Binds a data-set
         *
         * Preforms the hash algorithm on the
         * set of data provided and binds the
         * result to this hash.
         *
         * @param [in] data Data array to be hashed
         * @param [in] dLen Length of data array
         */
        void preformHash(const unsigned char* data, size_t dLen);
        /** @brief Algorithm name string access
         *
         * Returns the name of the current
         * algorithm string.  This function
         * requires an instantiated XOR hash.
         *
         * @return "XOR"
         */
        inline std::string algorithmName() const {return xorHash::staticAlgorithmName();}

        /** @brief Static 64 bit hash
         *
         * Hashes the provided data array
         * with the XOR algorithm, returning
         * a 64 bit XOR hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static xorHash hash64Bit(const unsigned char* data, size_t length){return xorHash(data,length,size::hash64);}
        /** @brief Static 128 bit hash
         *
         * Hashes the provided data array
         * with the XOR algorithm, returning
         * a 128 bit XOR hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static xorHash hash128Bit(const unsigned char* data, size_t length){return xorHash(data,length,size::hash128);}
        /** @brief Static 256 bit hash
         *
         * Hashes the provided data array
         * with the XOR algorithm, returning
         * a 256 bit XOR hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static xorHash hash256Bit(const unsigned char* data, size_t length){return xorHash(data,length,size::hash256);}
        /** @brief Static 512 bit hash
         *
         * Hashes the provided data array
         * with the XOR algorithm, returning
         * a 512 bit XOR hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static xorHash hash512Bit(const unsigned char* data, size_t length){return xorHash(data,length,size::hash512);}
    };
}

#endif