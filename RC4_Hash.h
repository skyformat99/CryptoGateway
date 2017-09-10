/**
 * Declares the RC-4 hash algorithm.
 * The RC-4 hashing algorithm is likely
 * secure, but not proven secure.
 **/

#ifndef RC4_HASH_H
#define RC4_HASH_H

#include <string>
#include <iostream>
#include <stdlib.h>

#include "cryptoHash.h"
#include "streamCipher.h"

namespace crypto {

	/** @brief RC-4 hash class
     *
     * This class defines an RC-4
     * based hash.  Note that this
     * hash is likely cryptographically
     * secure, but not proven cryptographically
     * secure.
     */
    class rc4Hash:public hash
    {
    private:
        /** @brief RC-4 hash constructor
         *
         * Constructs a hash with the data to
         * be hashed, the length of the array
         * and the size of the hash to be constructed.
         *
         * @param [in] data Data array
         * @param [in] length Length of data array
         * @param [in] size Size of hash
         */
        rc4Hash(const unsigned char* data, size_t length, uint16_t size);
    public:
        /** @brief Algorithm name string access
         *
         * Returns the name of the current
         * algorithm string.  This function
         * is static and can be accessed without
         * instantiating the class.
         *
         * @return "RC-4"
         */
        inline static std::string staticAlgorithmName() {return "RC-4";}
        /** @brief Algorithm ID number access
         *
         * Returns the ID of the current
         * algorithm.  This function
         * is static and can be accessed without
         * instantiating the class.
         *
         * @return crypto::algo::hashRC4
         */
        inline static uint16_t staticAlgorithm() {return algo::hashRC4;}

         /** @brief Default RC-4 hash constructor
         *
         * Constructs an empty RC-4 hash
         * class.
         */
        rc4Hash():hash(rc4Hash::staticAlgorithm()){}
        /** @brief Raw data copy
         *
         * Initializes the RC-4 hash
         * with a data array.  This
         * data array is not hashed
         * but assumed to represent
         * hashed data.
         *
         * @param [in] data Hashed data array
         * @param [in] size Size of hash array
         */
        rc4Hash(const unsigned char* data, uint16_t size);
        /** @brief RC-4 copy constructor
         *
         * Constructs an RC-4 hash with
         * another RC-4 hash.
         *
         * @param [in] cpy Hash to be copied
         */
        rc4Hash(const rc4Hash& cpy):hash(cpy){}
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
         * requires an instantiated RC-4 hash.
         *
         * @return "RC-4"
         */
        inline std::string algorithmName() const {return rc4Hash::staticAlgorithmName();}

        /** @brief Static 64 bit hash
         *
         * Hashes the provided data array
         * with the RC-4 algorithm, returning
         * a 64 bit RC-4 hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static rc4Hash hash64Bit(const unsigned char* data, size_t length){return rc4Hash(data,length,size::hash64);}
        /** @brief Static 128 bit hash
         *
         * Hashes the provided data array
         * with the RC-4 algorithm, returning
         * a 128 bit RC-4 hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static rc4Hash hash128Bit(const unsigned char* data, size_t length){return rc4Hash(data,length,size::hash128);}
        /** @brief Static 256 bit hash
         *
         * Hashes the provided data array
         * with the RC-4 algorithm, returning
         * a 256 bit RC-4 hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static rc4Hash hash256Bit(const unsigned char* data, size_t length){return rc4Hash(data,length,size::hash256);}
        /** @brief Static 512 bit hash
         *
         * Hashes the provided data array
         * with the RC-4 algorithm, returning
         * a 512 bit RC-4 hash.
         *
         * @param data Data array to be hashed
         * @param length Length of data array to be hashed
         * @return New xorHash
         */
        static rc4Hash hash512Bit(const unsigned char* data, size_t length){return rc4Hash(data,length,size::hash512);}
    };
}

#endif