/**
 * Implements the set of hex conversion
 * functions.  Consult hexConversion.h
 * for details.
 *
 */

///@cond INTERNAL

#ifndef HEX_CONVERSION_CPP
#define HEX_CONVERSION_CPP

#include "hexConversion.h"
#include "cryptoLogging.h"

//isHex char
bool crypto::isHexCharacter(char c)
{
    switch (c)
    {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
            return true;
        default:
            break;
    }
    return false;
}

//Converts a uint32 to hex
std::string crypto::toHex(unsigned char i)
{
    std::string ret="";
    for(int cnt=0;cnt<2;++cnt)
    {
        uint16_t temp=i&15;
        switch (temp)
        {
            case 0:
                ret='0'+ret;
                break;
            case 1:
                ret='1'+ret;
                break;
            case 2:
                ret='2'+ret;
                break;
            case 3:
                ret='3'+ret;
                break;
            case 4:
                ret='4'+ret;
                break;
            case 5:
                ret='5'+ret;
                break;
            case 6:
                ret='6'+ret;
                break;
            case 7:
                ret='7'+ret;
                break;
            case 8:
                ret='8'+ret;
                break;
            case 9:
                ret='9'+ret;
                break;
            case 10:
                ret='A'+ret;
                break;
            case 11:
                ret='B'+ret;
                break;
            case 12:
                ret='C'+ret;
                break;
            case 13:
                ret='D'+ret;
                break;
            case 14:
                ret='E'+ret;
                break;
            case 15:
                ret='F'+ret;
                break;
            default:
                cryptoerr<<"Hex conversion failed!"<<std::endl;
                return ret;
        }
        i=i>>4;
    }
    return ret;
}

//Converts a uint32 to hex
std::string crypto::toHex(uint32_t i)
{
    std::string ret="";
    for(int cnt=0;cnt<8;++cnt)
    {
        uint16_t temp=i&15;
        switch (temp)
        {
            case 0:
                ret='0'+ret;
                break;
            case 1:
                ret='1'+ret;
                break;
            case 2:
                ret='2'+ret;
                break;
            case 3:
                ret='3'+ret;
                break;
            case 4:
                ret='4'+ret;
                break;
            case 5:
                ret='5'+ret;
                break;
            case 6:
                ret='6'+ret;
                break;
            case 7:
                ret='7'+ret;
                break;
            case 8:
                ret='8'+ret;
                break;
            case 9:
                ret='9'+ret;
                break;
            case 10:
                ret='A'+ret;
                break;
            case 11:
                ret='B'+ret;
                break;
            case 12:
                ret='C'+ret;
                break;
            case 13:
                ret='D'+ret;
                break;
            case 14:
                ret='E'+ret;
                break;
            case 15:
                ret='F'+ret;
                break;
            default:
                cryptoerr<<"Hex conversion failed!"<<std::endl;
                return ret;
        }
        i=i>>4;
    }
    return ret;
}

//Converts a hex value to an unsigned char
unsigned char crypto::fromHex8(const std::string& str)
{
    unsigned char ret=0;

    for(int i=0;i<str.length()&&i<2;++i)
    {
        ret = ret<<4;
        switch (str[i])
        {
            case '0':
                break;
            case '1':
                ret=ret|1;
                break;
            case '2':
                ret=ret|2;
                break;
            case '3':
                ret=ret|3;
                break;
            case '4':
                ret=ret|4;
                break;
            case '5':
                ret=ret|5;
                break;
            case '6':
                ret=ret|6;
                break;
            case '7':
                ret=ret|7;
                break;
            case '8':
                ret=ret|8;
                break;
            case '9':
                ret=ret|9;
                break;
            case 'A':
                ret=ret|10;
                break;
            case 'B':
                ret=ret|11;
                break;
            case 'C':
                ret=ret|12;
                break;
            case 'D':
                ret=ret|13;
                break;
            case 'E':
                ret=ret|14;
                break;
            case 'F':
                ret=ret|15;
                break;
            default:
                break;
        }
    }
    return ret;
}
//Converts a hex value to a uint32_t
uint32_t crypto::fromHex32(const std::string& str)
{
    uint32_t ret=0;

    for(int i=0;i<str.length()&&i<8;++i)
    {
        ret = ret<<4;
        switch (str[i])
        {
            case '0':
                break;
            case '1':
                ret=ret|1;
                break;
            case '2':
                ret=ret|2;
                break;
            case '3':
                ret=ret|3;
                break;
            case '4':
                ret=ret|4;
                break;
            case '5':
                ret=ret|5;
                break;
            case '6':
                ret=ret|6;
                break;
            case '7':
                ret=ret|7;
                break;
            case '8':
                ret=ret|8;
                break;
            case '9':
                ret=ret|9;
                break;
            case 'A':
                ret=ret|10;
                break;
            case 'B':
                ret=ret|11;
                break;
            case 'C':
                ret=ret|12;
                break;
            case 'D':
                ret=ret|13;
                break;
            case 'E':
                ret=ret|14;
                break;
            case 'F':
                ret=ret|15;
                break;
            default:
                break;
        }
    }
    return ret;
}

#endif

///@endcond