/**
 * This file contains implementation of the
 * key bank tests and the end-to-end gateway
 * tests.  These tests are not exhaustive,
 * they test basic functionality of both
 * structures.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_TEST_CPP
#define GATEWAY_TEST_CPP

#include "gatewayTest.h"
#include "testKeyGeneration.h"
#include "../user.h"
#include <string>

using namespace test;
using namespace os;
using namespace crypto;


/*================================================================
	Key Bank Tests
 ================================================================*/

    //Basic key bank test
    void basicBankTest()
    {
        std::string locString = "gatewayTest.cpp, basicBankTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);
        cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
        cbank.addPair("GroupA","Name2",key->getD(),algo::publicRSA,size::public512);

        //Name1 by name
        os::smart_ptr<nodeGroup> found=cbank.find("GroupA","Name1");
        if(!found)
            generalTestException::throwException("Failed to find Name1 by name",locString);
        if(found->name()!="GroupA:Name1")
            generalTestException::throwException("Name1's name doesn't match (name)",locString);

        //Name1 by key
        found=cbank.find(key->getN(),algo::publicRSA,size::public512);
        if(!found)
            generalTestException::throwException("Failed to find Name1 by key",locString);
        if(found->name()!="GroupA:Name1")
            generalTestException::throwException("Name1's name doesn't match (key)",locString);

        //Name2 by name
        found=cbank.find("GroupA","Name2");
        if(!found)
            generalTestException::throwException("Failed to find Name2 by name",locString);
        if(found->name()!="GroupA:Name2")
            generalTestException::throwException("Name2's name doesn't match (name)",locString);
    }
    //Save/load test
    void bankSaveLoadTest()
    {
		std::string locString = "gatewayTest.cpp, bankSaveLoadTest()";
		try
		{
			avlKeyBank cbank("tempout.xml");
			if(cbank.numberErrors()==0)
				generalTestException::throwException("Found save file, should not have",locString);
            cbank.popError();
			os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);
			cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
			cbank.addPair("GroupA","Name2",key->getD(),algo::publicRSA,size::public512);
			cbank.save();
			if(cbank.numberErrors()>0)
				generalTestException::throwException("Failed to save XML file",locString);

            //Load
			avlKeyBank newBank("tempout.xml");
			if(newBank.numberErrors()>0)
            {
                auto err = newBank.popError();
                while(err)
                {
                    std::cout<<err->what()<<std::endl;
                    err = newBank.popError();
                }
				generalTestException::throwException("Failed to load XML file",locString);
            }

			 //Name1 by name
			os::smart_ptr<nodeGroup> found=newBank.find("GroupA","Name1");
			if(!found)
				generalTestException::throwException("Failed to find Name1 by name",locString);
			if(found->name()!="GroupA:Name1")
				generalTestException::throwException("Name1's name doesn't match (name)",locString);

			//Name1 by key
			found=newBank.find(key->getN(),algo::publicRSA,size::public512);
			if(!found)
				generalTestException::throwException("Failed to find Name1 by key",locString);
			if(found->name()!="GroupA:Name1")
				generalTestException::throwException("Name1's name doesn't match (key)",locString);

			//Name2 by name
			found=newBank.find("GroupA","Name2");
			if(!found)
				generalTestException::throwException("Failed to find Name2 by name",locString);
			if(found->name()!="GroupA:Name2")
				generalTestException::throwException("Name2's name doesn't match (name)",locString);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("tempout.xml");
			throw e;
		}
		catch(...)
		{
			os::delete_file("tempout.xml");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("tempout.xml");
    }
	//Merge test
	void bankMergeTest()
	{
		std::string locString = "gatewayTest.cpp, bankMergeTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key1=getStaticKeys<publicRSA>(size::public512,0);
		os::smart_ptr<publicRSA> key2=getStaticKeys<publicRSA>(size::public512,1);

		cbank.addPair("GroupA","Name1",key1->getN(),algo::publicRSA,size::public512);
        cbank.addPair("GroupA","Name2",key1->getD(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name3",key2->getN(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name4",key2->getN(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name2",key2->getD(),algo::publicRSA,size::public512);
		cbank.addPair("GroupA","Name2",key1->getN(),algo::publicRSA,size::public512);

		//Check to see if Name1 and Name2 point to the same group node
		os::smart_ptr<nodeGroup> found1=cbank.find("GroupA","Name1");
		os::smart_ptr<nodeGroup> found2=cbank.find("GroupA","Name2");
		if(found1!=found2)
			generalTestException::throwException("Double merge failed",locString);

		//Name merge check
		found1=cbank.find("GroupA","Name3");
		found2=cbank.find("GroupA","Name4");
		if(found1!=found2)
			generalTestException::throwException("Name merge failed",locString);

		//Key merge check
		found1=cbank.find(key1->getN(),algo::publicRSA,size::public512);
		found2=cbank.find(key2->getD(),algo::publicRSA,size::public512);
		if(found1!=found2)
			generalTestException::throwException("Key merge failed",locString);

		//Ensure some things haven't merged
		found1=cbank.find("GroupA","Name1");
		found2=cbank.find("GroupA","Name3");
		if(found1==found2)
			generalTestException::throwException("Too many merges occured",locString);
	}
	//Timestamp test: name
	void bankNameTimestampTest()
	{
		std::string locString = "gatewayTest.cpp, bankNameTimestampTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);

		cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
		os::sleep(2000);
        cbank.addPair("GroupA","Name2",key->getN(),algo::publicRSA,size::public512);

		//Set up array
		os::smart_ptr<nodeGroup> found=cbank.find("GroupA","Name1");
        if(!found)
            generalTestException::throwException("Failed to find node",locString);
		unsigned int size;
		auto arr=found->namesByTimestamp(size);

		//Check array
		if(size!=2)
			generalTestException::throwException("Name array size wrong",locString);
		if(arr[0]->name()!="Name2")
			generalTestException::throwException("First node wrong",locString);
		if(arr[1]->name()!="Name1")
			generalTestException::throwException("Second node wrong",locString);
	}
	//Timestamp test: key
	void bankKeyTimestampTest()
	{
		std::string locString = "gatewayTest.cpp, bankKeyTimestampTest()";
        avlKeyBank cbank;
        os::smart_ptr<publicRSA> key=getStaticKeys<publicRSA>(size::public512,0);

		cbank.addPair("GroupA","Name1",key->getN(),algo::publicRSA,size::public512);
		os::sleep(2000);
        cbank.addPair("GroupA","Name1",key->getD(),algo::publicRSA,size::public512);

		//Set up array
		os::smart_ptr<nodeGroup> found=cbank.find("GroupA","Name1");
        if(!found)
            generalTestException::throwException("Failed to find node",locString);
		unsigned int size;
		auto arr=found->keysByTimestamp(size);

		//Check array
		if(size!=2)
			generalTestException::throwException("Key array size wrong",locString);
		if(*(arr[0]->key())!=*(key->getD()))
			generalTestException::throwException("First node wrong",locString);
		if(*(arr[1]->key())!=*(key->getN()))
			generalTestException::throwException("Second node wrong",locString);
	}

/*================================================================
	User Test
 ================================================================*/

	//Basic user saving test
	void basicUserTest() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, basicBankTest()";

		try
		{
			user usr("testUser","TestFolder");
			if(!usr.needsSaving())
				generalTestException::throwException("User should call for save",locString);
			if(usr.numberErrors()>0)
				generalTestException::throwException("Unexpected user error!",locString);
			usr.save();

			//Check for basic file existance
			if(!os::check_exists("TestFolder"))
				generalTestException::throwException("Holding folder not created",locString);
			if(!os::check_exists("TestFolder/testUser"))
				generalTestException::throwException("User folder not created",locString);
			if(!os::check_exists("TestFolder/testUser/metaData.xml"))
				generalTestException::throwException("Meta data file not created",locString);
			if(!os::check_exists("TestFolder/testUser/keyBank.xml"))
				generalTestException::throwException("Key bank file not created",locString);

			//Set password
			std::string tempPass="password";
			usr.setPassword((unsigned char*)tempPass.c_str(),tempPass.length());
			if(!usr.needsSaving())
				generalTestException::throwException("User should have call for save after changing password",locString);
			usr.save();

			//Open a new user
			user nusr("testUser","TestFolder",(unsigned char*)tempPass.c_str(),tempPass.length());
			if(nusr.numberErrors()>0)
				generalTestException::throwException("Error when re-loading user data",locString);

			//Bad user
			user busr("testUser","TestFolder");
			if(busr.numberErrors()==0)
				generalTestException::throwException("Expected error for loading user without password",locString);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("TestFolder");
			throw e;
		}
		catch (...)
		{
			os::delete_file("TestFolder");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("TestFolder");
	}
	//Public-key test
	void userPublicKeyTest() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, userPublicKeyTest()";

		try
		{
			user usr("testUser","TestFolder");
			usr.save();
			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));
			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));
			usr.save();

			if(usr.numberErrors()>0)
				generalTestException::throwException("Unexpected user error!",locString);

			//Attempt to find keys
			os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(crypto::algo::publicRSA);
			pkfrm->setKeySize(crypto::size::public256);
			os::smart_ptr<publicKey> fnd=usr.findPublicKey(pkfrm);
			if(!fnd)
				generalTestException::throwException("Public key not found",locString);
			if(fnd->algorithm() != crypto::algo::publicRSA)
				generalTestException::throwException("Algorithm mis-match",locString);
			if(fnd->size() != crypto::size::public256)
				generalTestException::throwException("Size mis-match",locString);

			//Open a new user
			user nusr("testUser","TestFolder");
			if(nusr.numberErrors()>0)
				generalTestException::throwException("Error when re-loading user data",locString);

			//Compare old found to the default key
			if(!nusr.getDefaultPublicKey())
				generalTestException::throwException("No default public key loaded",locString);
			if(*nusr.getDefaultPublicKey()!=*fnd)
				generalTestException::throwException("Default public key incorrect",locString);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("TestFolder");
			throw e;
		}
		catch (...)
		{
			os::delete_file("TestFolder");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("TestFolder");
	}
	//Public-key iterative test
	void userPublicKeyIterate() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, userPublicKeyIterate()";

		try
		{
			user usr("testUser","TestFolder");
			usr.save();

			//First and last should be NULL
			if(usr.getFirstPublicKey())
				generalTestException::throwException("User has no public keys (get first)!",locString);
			if(usr.getLastPublicKey())
				generalTestException::throwException("User has no public keys (get last)!",locString);

			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));
			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));
			usr.save();

			if(usr.numberErrors()>0)
				generalTestException::throwException("Unexpected user error!",locString);
			auto trc=usr.getFirstPublicKey();
			int cnt=0;
			while(trc)
			{
				if(cnt>=2)
					generalTestException::throwException("Too many public keys in list",locString);
				if(cnt==0 && trc->size()!=crypto::size::public128)
					generalTestException::throwException("List order error (0)",locString);
				if(cnt==1 && trc->size()!=crypto::size::public256)
					generalTestException::throwException("List order error (1)",locString);
				++trc;
				++cnt;
			}

		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("TestFolder");
			throw e;
		}
		catch (...)
		{
			os::delete_file("TestFolder");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("TestFolder");
	}
	//Encrypted public key
	void encryptPublicKeyUser() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, encryptPublicKeyUser()";
		std::string tempPass="password";
		try
		{
			user usr("testUser","TestFolder",(unsigned char*)tempPass.c_str(),tempPass.length());
			usr.save();
			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));
			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));
			usr.save();

			if(usr.numberErrors()>0)
				generalTestException::throwException("Unexpected user error!",locString);

			//Attempt to find keys
			os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(crypto::algo::publicRSA);
			pkfrm->setKeySize(crypto::size::public256);
			os::smart_ptr<publicKey> fnd=usr.findPublicKey(pkfrm);
			if(!fnd)
				generalTestException::throwException("Public key not found",locString);
			if(fnd->algorithm() != crypto::algo::publicRSA)
				generalTestException::throwException("Algorithm mis-match",locString);
			if(fnd->size() != crypto::size::public256)
				generalTestException::throwException("Size mis-match",locString);

			//Open a new user
			user nusr("testUser","TestFolder",(unsigned char*)tempPass.c_str(),tempPass.length());
			if(nusr.numberErrors()>0)
				generalTestException::throwException("Error when re-loading user data",locString);

			//Compare old found to the default key
			if(!nusr.getDefaultPublicKey())
				generalTestException::throwException("No default public key loaded",locString);
			if(*nusr.getDefaultPublicKey()!=*fnd)
				generalTestException::throwException("Default public key incorrect",locString);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("TestFolder");
			throw e;
		}
		catch (...)
		{
			os::delete_file("TestFolder");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("TestFolder");
	}
	//Gateway settings test
	void gatewaySettingsUser() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, gatewaySettingsUser()";
		std::string tempPass="password";
		try
		{
			user usr("testUser","TestFolder",(unsigned char*)tempPass.c_str(),tempPass.length());
			usr.save();
			usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));
			os::smart_ptr<gatewaySettings> tstgrp=usr.insertSettings("testGroup");
			os::smart_ptr<gatewaySettings> defgrp=usr.findSettings("default");
			if(!tstgrp || !defgrp)
				generalTestException::throwException("Failed to intialize gateway settings",locString);

			usr.save();

			if(usr.numberErrors()>0)
				generalTestException::throwException("Unexpected user error!",locString);


			//Open a new user
			user nusr("testUser","TestFolder",(unsigned char*)tempPass.c_str(),tempPass.length());
			if(nusr.numberErrors()>0)
				generalTestException::throwException("Error when re-loading user data",locString);
			os::smart_ptr<gatewaySettings> temp=nusr.findSettings("default");
			if(!temp)
				generalTestException::throwException("default gateway settings not loaded",locString);
			if(*temp!=*defgrp)
				generalTestException::throwException("default gateway settings do not match",locString);
			temp=nusr.findSettings("testGroup");
			if(!temp)
				generalTestException::throwException("testGroup gateway settings not loaded",locString);
			if(*temp!=*tstgrp)
				generalTestException::throwException("testGroup gateway settings do not match",locString);
		}
		catch(os::smart_ptr<std::exception> e)
		{
			os::delete_file("TestFolder");
			throw e;
		}
		catch (...)
		{
			os::delete_file("TestFolder");
			throw os::smart_ptr<std::exception>(new unknownException(locString),os::shared_type);
		}
		os::delete_file("TestFolder");
	}

/*================================================================
	Gateway Test
 ================================================================*/

	//Gateway settings and ping reading
	void pingMessageTest() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, pingMessageTest()";

		user usr("testUser","");
		usr.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));
		os::smart_ptr<gatewaySettings> primaryGateway=usr.findSettings("default");
        if(!primaryGateway)
			generalTestException::throwException("No gateway settings from user",locString);
		os::smart_ptr<message> pingMsg=primaryGateway->ping();
		if(!pingMsg)
			generalTestException::throwException("No ping message created",locString);

		gatewaySettings compGateway(*pingMsg);

		//Run comparison checks
        if(primaryGateway->groupID()!=compGateway.groupID())
			generalTestException::throwException("Group IDs don't match",locString);
		if(primaryGateway->nodeName()!=compGateway.nodeName())
			generalTestException::throwException("Node names don't match",locString);

		if(!compGateway.getPublicKey())
			generalTestException::throwException("No public key in message-constructed settings",locString);
		if(compGateway.getPrivateKey())
			generalTestException::throwException("Found private key in message-constructed settings",locString);
		if(*primaryGateway->getPublicKey()!=*compGateway.getPublicKey())
			generalTestException::throwException("Public keys don't match",locString);
	}
	//Connects to gateways end-to-end
	void connectGatewayTest() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, connectGatewayTest()";

		user usr1("testUser1","");
		usr1.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));

		user usr2("testUser2","");
		usr2.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256,1)));

		gateway gtw1(&usr1);
		gateway gtw2(&usr2);

		//Mark 1
		os::smart_ptr<message> msg1=gtw1.getMessage();
		os::smart_ptr<message> msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark1)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark1)",locString);
		if(gtw1.currentState()!=gateway::SETTINGS_EXCHANGED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark1)",locString);
		if(gtw2.currentState()!=gateway::SETTINGS_EXCHANGED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark1)",locString);

		//Mark 2
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark2)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark2)",locString);
		if(gtw1.currentState()!=gateway::ESTABLISHING_STREAM)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark2)",locString);
		if(gtw2.currentState()!=gateway::ESTABLISHING_STREAM)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark2)",locString);

		//Mark 3
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark3)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark3)",locString);
		if(gtw1.currentState()!=gateway::STREAM_ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark3)",locString);
		if(gtw2.currentState()!=gateway::STREAM_ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark3)",locString);

		//Mark 4
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark4)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark4)",locString);
		if(gtw1.currentState()!=gateway::SIGNING_STATE)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark4)",locString);
		if(gtw2.currentState()!=gateway::SIGNING_STATE)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark4)",locString);

		//Mark 5
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark5)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark5)",locString);
		if(gtw1.currentState()!=gateway::CONFIRM_OLD)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark5)",locString);
		if(gtw2.currentState()!=gateway::CONFIRM_OLD)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark5)",locString);

		//Mark 6
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark6)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark6)",locString);
		if(gtw1.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark6)",locString);
		if(gtw2.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark6)",locString);

		//Mark 7
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark7)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark7)",locString);
		if(gtw1.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark7)",locString);
		if(gtw2.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark7)",locString);
		if(msg1->data()[0]!=message::SECURE_DATA_EXCHANGE)
			generalTestException::throwException("Unexpected message in gateway 1 (Mark7)",locString);
		if(msg2->data()[0]!=message::SECURE_DATA_EXCHANGE)
			generalTestException::throwException("Unexpected message in gateway 2 (Mark7)",locString);
	}
	//Message passing
	void messagePassGatewayTest() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, messagePassGatewayTest()";

		user usr1("testUser1","");
		usr1.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));

		user usr2("testUser2","");
		usr2.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));

		gateway gtw1(&usr1);
		gateway gtw2(&usr2);
		os::smart_ptr<message> msg1;
		os::smart_ptr<message> msg2;
		int cnt=0;

		while(!(gtw1.secure()&&gtw2.secure()) && cnt<10)
		{
			msg1=gtw1.getMessage();
			msg2=gtw2.getMessage();
			gtw1.processMessage(msg2);
			gtw2.processMessage(msg1);
			++cnt;
		}

		//Check if gateways are secured
		if(!gtw1.secure())
			generalTestException::throwException("Gateway 1 failed to secure",locString);
		if(!gtw2.secure())
			generalTestException::throwException("Gateway 2 failed to secure",locString);

		os::smart_ptr<message> pass1(new message(10),os::shared_type);
		os::smart_ptr<message> pass2(new message(10),os::shared_type);
		pass1->data()[0]=6;
		pass2->data()[0]=6;
		memcpy(pass1->data()+1,"message1\0",9);
		memcpy(pass2->data()+1,"message2\0",9);

		pass1=gtw1.send(pass1);
		pass2=gtw2.send(pass2);
		pass2=gtw1.processMessage(pass2);
		pass1=gtw2.processMessage(pass1);

		if(std::string((char*) pass1->data()+1)!="message1")
			generalTestException::throwException("Gateway 2 failed to process message 1",locString);
		if(std::string((char*) pass2->data()+1)!="message2")
			generalTestException::throwException("Gateway 1 failed to process message 2",locString);
		if(!gtw1.secure())
			generalTestException::throwException("Gateway 1 dropped connection",locString);
		if(!gtw2.secure())
			generalTestException::throwException("Gateway 2 dropped connection",locString);
	}
	//Sign with old keys
	void oldKeySigningTest() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, oldKeySigning()";

		user usr1("testUser1","");
		usr1.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));
		usr1.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));

		user usr2("testUser2","");
		usr2.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128,1)));
		usr2.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256,1)));

		usr1.getKeyBank()->addPair("default","testUser2",usr2.getLastPublicKey()->getN(),algo::publicRSA,size::public256);
		usr2.getKeyBank()->addPair("default","testUser1",usr1.getLastPublicKey()->getN(),algo::publicRSA,size::public256);

		gateway gtw1(&usr1);
		gateway gtw2(&usr2);

		//Mark 1
		os::smart_ptr<message> msg1=gtw1.getMessage();
		os::smart_ptr<message> msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark1)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark1)",locString);
		if(gtw1.currentState()!=gateway::SETTINGS_EXCHANGED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark1)",locString);
		if(gtw2.currentState()!=gateway::SETTINGS_EXCHANGED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark1)",locString);

		//Mark 2
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark2)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark2)",locString);
		if(gtw1.currentState()!=gateway::ESTABLISHING_STREAM)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark2)",locString);
		if(gtw2.currentState()!=gateway::ESTABLISHING_STREAM)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark2)",locString);

		//Mark 3
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark3)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark3)",locString);
		if(gtw1.currentState()!=gateway::STREAM_ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark3)",locString);
		if(gtw2.currentState()!=gateway::STREAM_ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark3)",locString);

		//Mark 4
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark4)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark4)",locString);
		if(gtw1.currentState()!=gateway::SIGNING_STATE)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark4)",locString);
		if(gtw2.currentState()!=gateway::SIGNING_STATE)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark4)",locString);

		//Mark 5
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark5)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark5)",locString);
		if(gtw1.currentState()!=gateway::CONFIRM_OLD)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark5)",locString);
		if(gtw2.currentState()!=gateway::CONFIRM_OLD)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark5)",locString);

		//Mark 6
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark6)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark6)",locString);
		if(gtw1.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark6)",locString);
		if(gtw2.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark6)",locString);

		//Mark 7
		msg1=gtw1.getMessage();
		msg2=gtw2.getMessage();
		gtw1.processMessage(msg2);
		gtw2.processMessage(msg1);
		if(gtw1.numberErrors()>0)
			generalTestException::throwException("Error in gateway 1 (Mark7)",locString);
		if(gtw2.numberErrors()>0)
			generalTestException::throwException("Error in gateway 2 (Mark7)",locString);
		if(gtw1.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 1 (Mark7)",locString);
		if(gtw2.currentState()!=gateway::ESTABLISHED)
			generalTestException::throwException("Unexpected state in gateway 2 (Mark7)",locString);
		if(msg1->data()[0]!=message::SECURE_DATA_EXCHANGE)
			generalTestException::throwException("Unexpected message in gateway 1 (Mark7)",locString);
		if(msg2->data()[0]!=message::SECURE_DATA_EXCHANGE)
			generalTestException::throwException("Unexpected message in gateway 2 (Mark7)",locString);
	}
    //Secure gateway through another gateway
    void gatewayForwardTest() throw (os::smart_ptr<std::exception>)
    {
        std::string locString = "gatewayTest.cpp, messagePassGatewayTest()";

        user usr1("testUser1","");
        usr1.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));

        user usr2("testUser2","");
        usr2.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public256)));

        user usr3("testUser3","");
        usr3.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128,1)));

        //A gateways
        gateway gtw1a(&usr1);
        gateway gtw2a(&usr2);
        os::smart_ptr<message> msg1;
        os::smart_ptr<message> msg2;
        int cnt=0;
        while(!(gtw1a.secure()&&gtw2a.secure()) && cnt<10)
        {
            msg1=gtw1a.getMessage();
            msg2=gtw2a.getMessage();
            gtw1a.processMessage(msg2);
            gtw2a.processMessage(msg1);
            ++cnt;
        }

        //B gateways
        gateway gtw1b(&usr2);
        gateway gtw2b(&usr3);
        cnt=0;
        while(!(gtw1b.secure()&&gtw2b.secure()) && cnt<10)
        {
            msg1=gtw1b.getMessage();
            msg2=gtw2b.getMessage();
            gtw1b.processMessage(msg2);
            gtw2b.processMessage(msg1);
            ++cnt;
        }

        //Check if gateways are secured
        if(!gtw1a.secure())
            generalTestException::throwException("Gateway 1A failed to secure",locString);
        if(!gtw2a.secure())
            generalTestException::throwException("Gateway 2A failed to secure",locString);
        if(!gtw1b.secure())
            generalTestException::throwException("Gateway 1B failed to secure",locString);
        if(!gtw2b.secure())
            generalTestException::throwException("Gateway 2B failed to secure",locString);
    }
	//Raw user message passing
	void rawGatewayMessage() throw (os::smart_ptr<std::exception>)
	{
		std::string locString = "gatewayTest.cpp, rawGatewayMessage()";

		user usr1("testUser1","");
		usr1.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));

        user usr2("testUser2","");
        usr2.addPublicKey(cast<publicKey,publicRSA>(getStaticKeys<publicRSA>(crypto::size::public128)));

		size_t len1;
		size_t len2;
		unsigned char* mes1;
		unsigned char* mes2;

		//Basic exchange
		mes1=usr1.unsignedIDMessage(len1);
		if(!mes1)
			generalTestException::throwException("Failed to generate (user 1)",locString);
		mes2=usr2.unsignedIDMessage(len2);
		if(!mes2)
		{
			delete [] mes1;
			generalTestException::throwException("Failed to generate (user 2)",locString);
		}

		if(!usr1.processIDMessage(mes2,len2))
		{
			delete [] mes1;
			delete [] mes2;
			generalTestException::throwException("Failed to process (user 1)",locString);
		}
		if(!usr2.processIDMessage(mes1,len1))
		{
			delete [] mes1;
			delete [] mes2;
			generalTestException::throwException("Failed to process (user 2)",locString);
		}
		delete [] mes1;
		delete [] mes2;

		//Secondary exchange
		mes1=usr1.unsignedIDMessage(len1,"default","testUser2");
		if(!mes1)
			generalTestException::throwException("Failed to generate (user 1)",locString);
		mes2=usr2.unsignedIDMessage(len2,"default","testUser1");
		if(!mes2)
		{
			delete [] mes1;
			generalTestException::throwException("Failed to generate (user 2)",locString);
		}

		if(!usr1.processIDMessage(mes2,len2))
		{
			delete [] mes1;
			delete [] mes2;
			generalTestException::throwException("Failed to process (user 1)",locString);
		}
		if(!usr2.processIDMessage(mes1,len1))
		{
			delete [] mes1;
			delete [] mes2;
			generalTestException::throwException("Failed to process (user 2)",locString);
		}
		delete [] mes1;
		delete [] mes2;

		//Basic message exchange
		unsigned char* processed_mes1;
		unsigned char* processed_mes2;
		mes1=usr1.encryptMessage(len1,(const unsigned char*)"message1",9,"default","testUser2");
		if(!mes1)
			generalTestException::throwException("Failed to generate (user 1)",locString);
		mes2=usr2.encryptMessage(len2,(const unsigned char*)"message2",9,"default","testUser1");
		if(!mes2)
		{
			delete [] mes1;
			generalTestException::throwException("Failed to generate (user 2)",locString);
		}
		processed_mes2=usr1.decryptMessage(len2,mes2,len2,"default","testUser2");
		processed_mes1=usr2.decryptMessage(len1,mes1,len1,"default","testUser1");
		delete [] mes1;
		delete [] mes2;

		if(processed_mes2==NULL || processed_mes1==NULL)
		{
			if(processed_mes1) delete [] processed_mes1;
			if(processed_mes2) delete [] processed_mes2;
			generalTestException::throwException("Failed to process message",locString);
		}
		if(std::string((char*)processed_mes1)!="message1")
		{
			delete [] processed_mes1;
			delete [] processed_mes2;
			generalTestException::throwException("Message 1 data mis-match",locString);
		}
		if(std::string((char*)processed_mes2)!="message2")
		{
			delete [] processed_mes1;
			delete [] processed_mes2;
			generalTestException::throwException("Message 2 data mis-match",locString);
		}
		delete [] processed_mes1;
		delete [] processed_mes2;
	}

/*================================================================
	Bind Suites
 ================================================================*/

    //Key bank test
    keyBankSuite::keyBankSuite():
        testSuite("Key Bank")
    {
        pushTest("Basics",&basicBankTest);
        pushTest("Save/Load",&bankSaveLoadTest);
		pushTest("Node Merging",&bankMergeTest);
		pushTest("Timestamp: Name",&bankNameTimestampTest);
		pushTest("Timestamp: Key",&bankKeyTimestampTest);
    }
	//User test
    userSuite::userSuite():
        testSuite("User")
    {
        pushTest("Basic Test",&basicUserTest);
		pushTest("Public Key",&userPublicKeyTest);
		pushTest("Public Key Iteration",&userPublicKeyIterate);
		pushTest("Encrypt Public Key",&encryptPublicKeyUser);
		pushTest("Gateway Settings",&gatewaySettingsUser);
    }
	//User test
	gatewaySuite::gatewaySuite():
        testSuite("Gateway")
    {
        pushTest("Ping",&pingMessageTest);
		pushTest("Full Connect",&connectGatewayTest);
		pushTest("Message Passing",&messagePassGatewayTest);
		pushTest("Old Key Signing",&oldKeySigningTest);
        pushTest("Gateway Forwarding",&gatewayForwardTest);
		pushTest("Raw Gateway Message",&rawGatewayMessage);
    }

#endif

///@endcond