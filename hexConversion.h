/**
 * Contains a set of functions to
 * convert integers and characters
 * from a hex string and converts
 * hex strings to integers and characters.
 *
 */

#ifndef HEX_CONVERSION_H
#define HEX_CONVERSION_H

#include <memory>
#include <stdint.h>
#include <cstdlib>
#include <iostream>
#include <string>

namespace crypto {

	/** @brief Check the character type
	 *
	 * Checks if the character is a valid
	 * hex character.  That is, 0-9 and A-F.
	 *
	 * @param [in] c Character to test
	 * @return true if a hex character, else, false
	 */
    bool isHexCharacter(char c);

	/** @brief Converts an 8 bit integer to a hex string
	 *
	 * @param [in] i Integer to convert
	 * @return i converted to hex string
	 */
    std::string toHex(unsigned char i);
	/** @brief Converts an 32 bit integer to a hex string
	 *
	 * @param [in] i Integer to convert
	 * @return i converted to hex string
	 */
    std::string toHex(uint32_t i);

	/** @brief Converts a hex string to an 8 bit integer
	 *
	 * @param [in] str Hex string to convert
	 * @return str converted to integer
	 */
    unsigned char fromHex8(const std::string& str);
	/** @brief Converts a hex string to an 32 bit integer
	 *
	 * @param [in] str Hex string to convert
	 * @return str converted to integer
	 */
    uint32_t fromHex32(const std::string& str);
}

#endif