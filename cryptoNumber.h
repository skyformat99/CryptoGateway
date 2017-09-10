/**
 * Contains declarations of large numbers
 * for usage inside the CryptoGateway.  The
 * two numbers defined in this file are the
 * general structure for large numbers and
 * a basic integer.
 *
 */

#ifndef CRYPTO_NUMBER_H
#define CRYPTO_NUMBER_H

#include "Datastructures/Datastructures.h"
#include "hexConversion.h"
#include "cryptoConstants.h"
#include "cryptoCHeaders.h"
#include <string>

namespace crypto
{
	///@cond INTERNAL
    class number;
	///@endcond

	/** @brief Output stream operator
	 *
	 * @param [in/out] os Output stream
	 * @param [in] num Number to be output
	 *
	 * @return reference to std::ostream& os
	 */
    std::ostream& operator<<(std::ostream& os, const number& num);
	/** @brief Input stream operator
	 *
	 * @param [in/out] is Input stream
	 * @param [in] num Number to set with the string
	 *
	 * @return reference to std::istream& is
	 */
    std::istream& operator>>(std::istream& is, number& num);

    /** @brief Basic number definition
	 *
	 * This class defines the basics
	 * of all large number classes.
	 * Operators are specifically defined
	 * in each class which inherits from number.
	 */
    class number
    {
    protected:
		/** @brief Definition of number algorithms
		 */
        struct numberType* _numDef;
		/** @brief Size of the data array
		 */
        uint16_t _size;
		/** @brief Data array
		 */
        uint32_t* _data;

		/** @brief Compares two numbers
		 * @param [in] n2 Number to be compared against
		 * @return 0 if equal, 1 if greater than, -1 if less than
		 */
        int _compare(const number& n2) const;
    public:
		/** @brief Construct with number definition
		 * @param [in] numDef Definition of number, by default buildNullNumberType()
		 */
        number(struct numberType* numDef=buildNullNumberType());
		/** @brief Construct with size
		 * @param [in] size Size of the number to be constructed
		 * @param [in] numDef Definition of number, by default buildNullNumberType()
		 */
        number(uint16_t size, struct numberType* numDef=buildNullNumberType());
		/** @brief Construct with data array
		 * @param [in] d Data array to bind to this number
		 * @param [in] size Size of the number to be constructed
		 * @param [in] numDef Definition of number, by default buildNullNumberType()
		 */
        number(const uint32_t* d, uint16_t size, struct numberType* numDef=buildNullNumberType());
		/** @brief Copy constructor
		 * @param [in] num Number used to construct this
		 */
        number(const number& num);
		/** @brief Equality constructor
		 * @param [in] num Number used to re-build this
		 * @return Reference to this
		 */
		number& operator=(const number& num);
		/** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~number();

        /** @brief Eliminate high-order zeros
		 * @return void
		 */
        void reduce();
		/** @brief Expand number size
		 * @param [in] size Size of the number to be constructed
		 * @return void
		 */
        void expand(uint16_t size);

		/** @brief Build byte array
		 *
		 * Constructs a byte array based on the
		 * data array of this number.  Useful for
		 * binary saving and packet-izing.
		 *
		 * @param [out] arr_len
		 * return Byte array
		 */
		os::smart_ptr<unsigned char> getCharData(size_t& arr_len) const;
		/** @brief Build compatibility byte array
		 *
		 * Constructs a byte array based on the
		 * data array of this number.  First
		 * eliminates endian differences of
		 * operating systems.
		 *
		 * @param [out] arr_len
		 * return Byte array
		 */
		os::smart_ptr<unsigned char> getCompCharData(size_t& arr_len) const;

        /** @brief Build hex string from number
		 * @return Hex string
		 */
        std::string toString() const;
		/** @brief Re-builds number from provided string
		 * @param [in] str Hex string representing number
		 * @return void
		 */
        void fromString(const std::string& str);

		/** @brief Read-only data access
		 * @param [in] pos Index to access
		 * @return crypto::number::_data[pos]
		 */
		uint32_t operator[](uint16_t pos) const;
		/** @brief Read/write data access
		 * @param [in] pos Index to access
		 * @return crypto::number::_data[pos]
		 */
		uint32_t& operator[](uint16_t pos);

        /** @brief '==' comparison operator
		 * @param [in] comp Number to be compared against
		 * @return this == comp
		 */
        const bool operator==(const number& comp) const;
		/** @brief '!=' comparison operator
		 * @param [in] comp Number to be compared against
		 * @return this != comp
		 */
        const bool operator!=(const number& comp) const;
        /** @brief '<=' comparison operator
		 * @param [in] comp Number to be compared against
		 * @return this <= comp
		 */
		const bool operator<=(const number& comp) const;
        /** @brief '>=' comparison operator
		 * @param [in] comp Number to be compared against
		 * @return this >= comp
		 */
		const bool operator>=(const number& comp) const;
        /** @brief '<' comparison operator
		 * @param [in] comp Number to be compared against
		 * @return this < comp
		 */
		const bool operator<(const number& comp) const;
        /** @brief '>' comparison operator
		 * @param [in] comp Number to be compared against
		 * @return this > comp
		 */
		const bool operator>(const number& comp) const;

        /** @brief Compares two numbers
		 * @param [in] n2 Number to be compared against
		 * @return 0 if equal, 1 if greater than, -1 if less than
		 */
        int compare(const number* n2) const;
		/** @brief Addition function
		 *
		 * Preforms this+n2=result.  Note
		 * that this function will only preform
		 * the addition if the number definition
		 * defines an addition function.
		 *
		 * @param [in] n2 Number to be added
		 * @param [out] result Result of addition
		 * @return void
		 */
        void addition(const number* n2, number* result) const;
        /** @brief Subtraction function
		 *
		 * Preforms this-n2=result.  Note
		 * that this function will only preform
		 * the subtraction if the number definition
		 * defines an subtraction function.
		 *
		 * @param [in] n2 Number to be subtracted
		 * @param [out] result Result of subtraction
		 * @return void
		 */
		void subtraction(const number* n2, number* result) const;
        /** @brief Right shift function
		 *
		 * Preforms this>>n2=result.  Note
		 * that this function will only preform
		 * the shift if the number definition
		 * defines an rightShift function.
		 *
		 * @param [in] n2 Bits to be shifted by
		 * @param [out] result Result of shift
		 * @return void
		 */
		void rightShift(uint16_t n2, number* result) const;
        /** @brief Left shift function
		 *
		 * Preforms this<<n2=result.  Note
		 * that this function will only preform
		 * the shift if the number definition
		 * defines an leftShift function.
		 *
		 * @param [in] n2 Bits to be shifted by
		 * @param [out] result Result of shift
		 * @return void
		 */
		void leftShift(uint16_t n2, number* result) const;
        /** @brief Multiplication function
		 *
		 * Preforms this*n2=result.  Note
		 * that this function will only preform
		 * the multiplication if the number definition
		 * defines an multiplication function.
		 *
		 * @param [in] n2 Number to be multiplied
		 * @param [out] result Result of multiplication
		 * @return void
		 */
		void multiplication(const number* n2, number* result) const;
        /** @brief Division function
		 *
		 * Preforms this/n2=result.  Note
		 * that this function will only preform
		 * the division if the number definition
		 * defines an division function.
		 *
		 * @param [in] n2 Number to be divided by
		 * @param [out] result Result of division
		 * @return void
		 */
		void division(const number* n2, number* result) const;
		/** @brief Modulo function
		 *
		 * Preforms this%n2=result.  Note
		 * that this function will only preform
		 * the modulo if the number definition
		 * defines an modulo function.
		 *
		 * @param [in] n2 Number to be moded by
		 * @param [out] result Result of modulo
		 * @return void
		 */
		void modulo(const number* n2, number* result) const;
        /** @brief Exponentiation function
		 *
		 * Preforms this^n2=result.  Note
		 * that this function will only preform
		 * the exponentiation if the number definition
		 * defines an exponentiation function.
		 *
		 * @param [in] n2 Number to be raised to
		 * @param [out] result Result of exponentiation
		 * @return void
		 */
		void exponentiation(const number* n2, number* result) const;
        /** @brief Modular exponentiation
		 *
		 * Preforms this^n2 %n3=result.  Note
		 * that this function will only preform
		 * the modular exponentiation if the number definition
		 * defines an modular exponentiation function.
		 *
		 * @param [in] n2 Number to be raised to
		 * @param [in] n3 Number defines modulo space
		 * @param [out] result Result of exponentiation
		 * @return void
		 */
		void moduloExponentiation(const number* n2, const number* n3, number* result) const;
        /** @brief Greatest-common-denominator function
		 *
		 * Preforms GCD of this and n2=result.  Note
		 * that this function will only preform
		 * the greatest-common-denominator if the number definition
		 * defines an greatest-common-denominator function.
		 *
		 * @param [in] n2 GCD target
		 * @param [out] result Result of greatest-common-denominator
		 * @return void
		 */
		void gcd(const number* n2,number* result) const;
        /** @brief Modular-inverse function
		 *
		 * Preforms (this^-1)%n2=result.  Note
		 * that this function will only preform
		 * the modular-inverse if the number definition
		 * defines an modular-inverse function.
		 *
		 * @param [in] n2 Number which defines the modulo space
		 * @param [out] result Result of modular-inverse
		 * @return void
		 */
		void modInverse(const number* n2, number* result) const;

        /** @brief Or operator
		 *
		 * Preforms bitwise or on the number.
		 * Note that all numbers can preform
		 * bit-wise operations on all other
		 * numbers
		 *
		 * @param [in] op Number preforming bitwise operation
		 * @return this | op
		 */
        number operator|(const number& op) const;
		/** @brief Or-equals operator
		 *
		 * Preforms bitwise or-equals on the number.
		 * Note that all numbers can preform
		 * bit-wise operations on all other
		 * numbers
		 *
		 * @param [in] op Number preforming bitwise operation
		 * @return this = this | op
		 */
        number& operator|=(const number& op);
		/** @brief And operator
		 *
		 * Preforms bitwise and on the number.
		 * Note that all numbers can preform
		 * bit-wise operations on all other
		 * numbers
		 *
		 * @param [in] op Number preforming bitwise operation
		 * @return this & op
		 */
        number operator&(const number& op) const;
		/** @brief And-equals operator
		 *
		 * Preforms bitwise and-equals on the number.
		 * Note that all numbers can preform
		 * bit-wise operations on all other
		 * numbers
		 *
		 * @param [in] op Number preforming bitwise operation
		 * @return this = this & op
		 */
        number& operator&=(const number& op);
        /** @brief X-Or operator
		 *
		 * Preforms bitwise exclusive-or on the number.
		 * Note that all numbers can preform
		 * bit-wise operations on all other
		 * numbers
		 *
		 * @param [in] op Number preforming bitwise operation
		 * @return this ^ op
		 */
		number operator^(const number& op) const;
		/** @brief X-Or-equals operator
		 *
		 * Preforms bitwise exclusive-or-equals on the number.
		 * Note that all numbers can preform
		 * bit-wise operations on all other
		 * numbers
		 *
		 * @param [in] op Number preforming bitwise operation
		 * @return this=this ^ op
		 */
        number& operator^=(const number& op);
		/** @brief Negate operator
		 *
		 * Flips all bits in the number,
		 * returning a new number.
		 *
		 * @return ~this
		 */
        number operator~() const;

        /** @brief Check if the number is valid
		 *
		 * By default, this function returns false.
		 * Numbers which inherit this class are expected
		 * to use this function to check if the number
		 * definition matches the class definition.
		 *
		 * @return true if valid type, else, false
		 */
        inline virtual bool checkType() const {return false;}
        /** @brief Check for the 'compare' function
		 * @return crypto::number::_numDef->compare
		 */
		inline bool hasCompare() const {return _numDef->compare;}
		/** @brief Check for the 'addition' function
		 * @return crypto::number::_numDef->addition
		 */
        inline bool hasAddition() const {return _numDef->addition;}
		/** @brief Check for the 'subtraction' function
		 * @return crypto::number::_numDef->subtraction
		 */
        inline bool hasSubtraction() const {return _numDef->subtraction;}
		/** @brief Check for the 'rightShift' function
		 * @return crypto::number::_numDef->rightShift
		 */
        inline bool hasRightShift() const {return _numDef->rightShift;}
		/** @brief Check for the 'leftShift' function
		 * @return crypto::number::_numDef->leftShift
		 */
        inline bool hasLeftShift() const {return _numDef->leftShift;}
		/** @brief Check for the 'multiplication' function
		 * @return crypto::number::_numDef->multiplication
		 */
        inline bool hasMultiplication() const {return _numDef->multiplication;}
		/** @brief Check for the 'division' function
		 * @return crypto::number::_numDef->division
		 */
        inline bool hasDivision() const {return _numDef->division;}
		/** @brief Check for the 'modulo' function
		 * @return crypto::number::_numDef->modulo
		 */
        inline bool hasModulo() const {return _numDef->modulo;}
		/** @brief Check for the 'exponentiation' function
		 * @return crypto::number::_numDef->exponentiation
		 */
        inline bool hasExponentiation() const {return _numDef->exponentiation;}
		/** @brief Check for the 'moduloExponentiation' function
		 * @return crypto::number::_numDef->moduloExponentiation
		 */
        inline bool hasModuloExponentiation() const {return _numDef->moduloExponentiation;}
		/** @brief Check for the 'gcd' function
		 * @return crypto::number::_numDef->gcd
		 */
        inline bool hasGCD() const {return _numDef->gcd;}
		/** @brief Check for the 'modInverse' function
		 * @return crypto::number::_numDef->modInverse
		 */
        inline bool hasModInverse() const {return _numDef->modInverse;}

		/** @brief Access data size
		 * @return crypto::number::_size
		 */
        uint16_t size() const{return _size;}
		/** @brief Data access
		 * @return crypto::number::_data
		 */
        uint32_t* data() {return _data;}
		/** @brief Constant data access
		 * @return crypto::number::_data
		 */
        const uint32_t* data() const{return _data;}

        /** @brief Access number definition
		 * @return crypto::number::_numDef
		 */
        inline const struct numberType* numberDefinition() const {return _numDef;}
		/** @brief Access number ID
		 * @return crypto::number::_numDef->typeID
		 */
        inline int typeID() const {return _numDef->typeID;}
		/** @brief Access number name
		 * @return crypto::number::_numDef->name
		 */
        inline std::string name() const {return std::string(_numDef->name);}

        /** @brief Cast to a size_t for hashing
         * ALlows data structures to cast this
         * object to a size_t for hash tables.
         * @return void
         */
        inline operator size_t() const {return os::hashData((const char*)_data, sizeof(uint32_t)*_size);}
    };

    /** @brief Integer number definition
	 *
	 * A traditional numerical definition
	 * which can be of arbitrary size.
	 */
    class integer:public number
    {
    public:
        /** @brief Constructs a '0' integer
		 * @return 0
		 */
        static integer zero(){return integer();}
		/** @brief Constructs a '1' integer
		 * @return 1
		 */
        static integer one();
		/** @brief Constructs a '2' integer
		 * @return 2
		 */
		static integer two();

		/** @brief Default integer constructor
		 */
        integer();
		/** @brief Construct integer with size
		 * @param [in] size Size integer is initialized with
		 */
        integer(uint16_t size);
		/** @brief Construct integer with data array
		 * @param [in] d Data array to be bound
		 * @param [in] size Size of array
		 */
        integer(const uint32_t* d, uint16_t size);
		/** @brief Copy constructor
		 * @param [in] num Integer used to construct this
		 */
        integer(const integer& num);
        /** @brief Virtual destructor
         *
         * Destructor must be virtual, if an object
         * of this type is deleted, the destructor
         * of the type which inherits this class should
         * be called.
         */
        virtual ~integer(){}

        /** @brief Check if the number is valid
		 *
		 * Checks to ensure that the number definition
		 * for this object is the Base-10 type.  Ensure
		 * that all basic mathematical operators are defined.
		 *
		 * @return true if valid type, else, false
		 */
        bool checkType() const;

        /** @brief Allows integer to be cast as a number
		 * @return number(*this)
		 */
        inline operator number()const{return number((number)*this);}
        /** @brief Integer addition operator
		 * @param [in] n Integer to be added
		 * @reutrn this + n
		 */
		integer operator+(const integer& n) const;
		/** @brief Integer addition equals operator
		 * @param [in] n Integer to be added
		 * @reutrn this = this + n
		 */
        integer& operator+=(const integer& n);
		/** @brief Increment operator
		 * @return ++this
		 */
        integer& operator++();
		/** @brief Increment operator
		 * @return this++-
		 */
        integer operator++(int dummy);

		/** @brief Integer subtraction operator
		 * @param [in] n Integer to be subtracted
		 * @reutrn this - n
		 */
        integer operator-(const integer& n) const;
		/** @brief Integer subtraction equals operator
		 * @param [in] n Integer to be subtracted
		 * @reutrn this = this - n
		 */
        integer& operator-=(const integer& n);
        /** @brief Decrement operator
		 * @return --this
		 */
		integer& operator--();
        /** @brief Decrement operator
		 * @return this--
		 */
		integer operator--(int dummy);

		/** @brief Right shift operator
		 * @param [in] n Number of bits to shift
		 * @return this >> n
		 */
        integer operator>>(unsigned n) const;
		/** @brief Left shift operator
		 * @param [in] n Number of bits to shift
		 * @return this << n
		 */
        integer operator<<(unsigned n) const;

		/** @brief Integer multiplication operator
		 * @param [in] n Integer to be multiplied
		 * @reutrn this * n
		 */
        integer operator*(const integer& n) const;
		/** @brief Integer multiplication equals operator
		 * @param [in] n Integer to be multiplied
		 * @reutrn this = this * n
		 */
        integer& operator*=(const integer& n);

		/** @brief Integer division operator
		 * @param [in] n Integer to be divided by
		 * @reutrn this / n
		 */
        integer operator/(const integer& n) const;
		/** @brief Integer division equals operator
		 * @param [in] n Integer to be divided by
		 * @reutrn this = this / n
		 */
        integer& operator/=(const integer& n);

		/** @brief Integer modulo operator
		 * @param [in] n Integer defining modulo space
		 * @reutrn this % n
		 */
        integer operator%(const integer& n) const;
		/** @brief Integer modulo equals operator
		 * @param [in] n Integer defining modulo space
		 * @reutrn this = this % n
		 */
        integer& operator%=(const integer& n);

		/** @brief Integer exponentiation function
		 * @param [in] n Integer to be raised to
		 * @return this^n
		 */
        integer exponentiation(const integer& n) const;
		/** @brief Integer exponentiation equals function
		 * @param [in] n Integer to be raised to
		 * @return this = this^n
		 */
        integer& exponentiationEquals(const integer& n);
		/** @brief Integer modulo-exponentiation function
		 * @param [in] n Integer to be raised to
		 * @param [in] mod Integer representing modulo space
		 * @return this^n % mod
		 */
        integer moduloExponentiation(const integer& n, const integer& mod) const;
		/** @brief Integer modulo-exponentiation equals function
		 * @param [in] n Integer to be raised to
		 * @param [in] mod Integer representing modulo space
		 * @return this = this^n % mod
		 */
        integer& moduloExponentiationEquals(const integer& n, const integer& mod);
		/** @brief Integer GCD function
		 * @param [in] n Integer to be compared against
		 * @return GCD of this and n
		 */
        integer gcd(const integer& n) const;
		/** @brief Integer GCD equals function
		 * @param [in] n Integer to be compared against
		 * @return this = GCD of this and n
		 */
        integer& gcdEquals(const integer& n);
		/** @brief Integer modular inverse function
		 * @param [in] n Integer representing modulo space
		 * @return (this^-1) % n
		 */
        integer modInverse(const integer& m) const;
		/** @brief Integer modular inverse equals function
		 * @param [in] n Integer representing modulo space
		 * @return this = (this^-1) % n
		 */
        integer& modInverseEquals(const integer& n);

		/** @brief Test if this integer is prime
		 *
		 * Preforms a probabilistic prime test
		 * on this number.  This operation can
		 * be quite expensive, especially for
		 * large numbers.
		 *
		 * @param [in] testVal Number of test cycles, crytpo::algo::primeTestCycle by default
		 * @return true if prime, else, false
		 */
        bool prime(uint16_t testVal=algo::primeTestCycle) const;
    };
}

#endif