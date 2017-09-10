/**
 * Provides functions to save and load XML trees in
 * encrypted files.
 **/

#ifndef XML_ENCRYPTION_H
#define XML_ENCRYPTION_H

#include "streamPackage.h"
#include "publicKeyPackage.h"

namespace crypto {

	///@cond INTERNAL
	    class keyBank;
		class nodeGroup;
    ///@endcond

    //XML encryption output
	bool EXML_Output(std::string path, os::smart_ptr<os::XMLNode> head, unsigned char* symKey,size_t passwordLength, os::smart_ptr<streamPackageFrame> spf=NULL);
    bool EXML_Output(std::string path, os::smart_ptr<os::XMLNode> head, std::string password, os::smart_ptr<streamPackageFrame> spf=NULL);

    bool EXML_Output(std::string path, os::smart_ptr<os::XMLNode> head, os::smart_ptr<publicKey> pbk,unsigned int lockType=file::PRIVATE_UNLOCK,os::smart_ptr<streamPackageFrame> spf=NULL);
	bool EXML_Output(std::string path, os::smart_ptr<os::XMLNode> head, os::smart_ptr<number> publicKey,unsigned int pkAlgo,size_t pkSize,os::smart_ptr<streamPackageFrame> spf=NULL);

    //XML decryption input
	os::smart_ptr<os::XMLNode> EXML_Input(std::string path, unsigned char* symKey,size_t passwordLength);
    os::smart_ptr<os::XMLNode> EXML_Input(std::string path, std::string password);
	os::smart_ptr<os::XMLNode> EXML_Input(std::string path, os::smart_ptr<publicKey> pbk,os::smart_ptr<keyBank> kyBank,os::smart_ptr<nodeGroup>& author);
    os::smart_ptr<os::XMLNode> EXML_Input(std::string path, os::smart_ptr<publicKey> pbk);
	os::smart_ptr<os::XMLNode> EXML_Input(std::string path, os::smart_ptr<keyBank> kyBank);
	os::smart_ptr<os::XMLNode> EXML_Input(std::string path, os::smart_ptr<keyBank> kyBank,os::smart_ptr<nodeGroup>& author);
}

#endif
