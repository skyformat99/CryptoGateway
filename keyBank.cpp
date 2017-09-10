/**
 * This file contians the implimentation for the
 * crypto::avlKeyBank and supporting classes.
 * Consult keyBank.h for details.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_CPP
#define GATEWAY_CPP

#include "keyBank.h"
#include "cryptoError.h"
#include "XMLEncryption.h"
#include <sstream>

namespace crypto {

/*-----------------------------------
     Node Group
  -----------------------------------*/

    //Constructs a nodeName with an XML tree
	nodeGroup::nodeGroup(keyBank* master,os::smart_ptr<os::XMLNode> fileNode)
	{
		if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
		_master=master;
		sortingLock.lock();
		try
		{
			if(fileNode->id()!="nodeGroup") throw errorPointer(new fileFormatError(),os::shared_type);

			//Names
			auto list1=fileNode->searchList("names");
			if(list1.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
			os::smart_ptr<os::XMLNode> secondLevel=&list1.first();
			auto list2=secondLevel->searchList("name");
			if(list2.size()<=0) throw errorPointer(new fileFormatError(),os::shared_type);

			//Insert name block
			for(auto block=list2.first();block;++block)
			{
				//Group
				auto parseList=block->searchList("group");
				if(parseList.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				std::string gn=parseList.first()->data();

				//Name
				parseList=block->searchList("name");
				if(parseList.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				std::string nm=parseList.first()->data();

				//Timestamp
				parseList=block->searchList("timestamp");
				if(parseList.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				uint64_t times=0;
				std::stringstream(parseList.first()->data())>>times;
				if(times==0) throw errorPointer(new fileFormatError(),os::shared_type);

				//Construct
				os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,gn,nm,times),os::shared_type);
				if(nameList.insert(nameInsert))
					_master->pushNewNode(nameInsert);
			}

			//Keys
			list1=fileNode->searchList("keys");
			if(list1.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
			secondLevel=&list1.first();
			list2=secondLevel->searchList("key");
			if(list2.size()<=0) throw errorPointer(new fileFormatError(),os::shared_type);

			//Insert key block
			for(auto block=list2.first();block;++block)
			{
				//Key size
				auto parseList=block->searchList("keySize");
				if(parseList.size()!=1)
                    throw errorPointer(new fileFormatError(),os::shared_type);
				uint16_t ks=std::stoi(parseList.first()->data())/32;

				//Algo ID
				parseList=block->searchList("algo");
				if(parseList.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				std::string ali=parseList.first()->data();

				//Timestamp
				parseList=block->searchList("timestamp");
				if(parseList.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				uint64_t times=0;
				std::stringstream(parseList.first()->data())>>times;
				if(times==0) throw errorPointer(new fileFormatError(),os::shared_type);

				//Key
				parseList=block->searchList("key");
				if(parseList.size()!=1) throw errorPointer(new fileFormatError(),os::shared_type);
				auto hld=&parseList.first();
				if(hld->dataList().size()!=ks) throw errorPointer(new fileFormatError(),os::shared_type);
				os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(ali);
				if(!pkfrm) throw errorPointer(new fileFormatError(),os::shared_type);
				pkfrm->getCopy();
				if(!pkfrm) throw errorPointer(new fileFormatError(),os::shared_type);
				pkfrm->setKeySize(ks);
				uint32_t* keyArr=new uint32_t[ks];
				for(unsigned int arrcnt=0;arrcnt<ks;++arrcnt)
					std::stringstream(hld->dataList()[arrcnt])>>keyArr[arrcnt];
				os::smart_ptr<number> key=pkfrm->convert(keyArr,ks);
				delete [] keyArr;

				//Construct
				os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,pkfrm->algorithm(),ks,times),os::shared_type);
				if(keyList.insert(keyInsert))
					_master->pushNewNode(keyInsert);
			}

			//Sort inserted elements
			sortKeys();
			sortNames();
		}
		catch(errorPointer e)
		{
			sortingLock.unlock();
			throw e;
		}
		catch(...)
		{
			sortingLock.unlock();
			throw errorPointer(new unknownErrorType(),os::shared_type);
		}
		sortingLock.unlock();
	}
	//Node group constructor
    nodeGroup::nodeGroup(keyBank* master,std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
		if(groupName.size()>size::GROUP_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);
		if(name.size()>size::NAME_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);

		_master=master;
		try
		{
			sortingLock.lock();
			os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,groupName,name),os::shared_type);
			if(nameList.insert(nameInsert))
				_master->pushNewNode(nameInsert);
			else throw errorPointer(new insertionFailed(),os::shared_type);
			os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,algoID,keySize),os::shared_type);
			if(keyList.insert(keyInsert))
				_master->pushNewNode(keyInsert);
			else throw errorPointer(new insertionFailed(),os::shared_type);
			sortKeys();
			sortNames();
		}
		catch(errorPointer e)
		{
			sortingLock.unlock();
			throw e;
		}
		catch(...)
		{
			sortingLock.unlock();
			throw errorPointer(new unknownErrorType(),os::shared_type);
		}
		sortingLock.unlock();
    }
	//Returns the name of a node group
	void nodeGroup::getName(std::string& groupName,std::string& name)
	{
		sortingLock.lock();

		//No array case
		if(!sortedNames || !sortedNames[0])
		{
            os::smart_ptr<nodeNameReference> ref=sortedNames[0];
			groupName="";
			name="";
		}
		else
		{
			groupName=sortedNames[0]->groupName();
			name=sortedNames[0]->name();
		}
		sortingLock.unlock();
	}
	//Returns the name of a node group
	std::string nodeGroup::name()
	{
		std::string gn,nm;
		getName(gn,nm);
		return gn+":"+nm;
	}

	//Merges two node groups
	void nodeGroup::merge(nodeGroup& source)
	{
		sortingLock.lock();
		if(source._master!=_master) throw errorPointer(new masterMismatch(),os::shared_type);
		auto trc1=source.nameList.first();
		while(trc1)
		{
			trc1->_master=this;
			nameList.insert(&trc1);
			++trc1;
		}
		auto trc2=source.keyList.first();
		while(trc2)
		{
			trc2->_master=this;
			keyList.insert(&trc2);
			++trc2;
		}
		sortKeys();
		sortNames();
		sortingLock.unlock();
	}
	//Adds an alias to the current node
	void nodeGroup::addAlias(std::string groupName,std::string name,uint64_t timestamp)
	{
		sortingLock.lock();
		os::smart_ptr<nodeNameReference> nameInsert(new nodeNameReference(this,groupName,name,timestamp),os::shared_type);
        if(nameList.insert(nameInsert))
			_master->pushNewNode(nameInsert);
		sortNames();
		sortingLock.unlock();
	}
	//Adds a key to the current node
	void nodeGroup::addKey(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp)
	{
		sortingLock.lock();
		os::smart_ptr<nodeKeyReference> keyInsert(new nodeKeyReference(this,key,algoID,keySize,timestamp),os::shared_type);
        if(keyList.insert(keyInsert))
			_master->pushNewNode(keyInsert);
		sortKeys();
		sortingLock.unlock();
	}

	//Compare keys by timestamp
	int compareKeysByTimestamp(const os::smart_ptr<nodeKeyReference>& ref1, const os::smart_ptr<nodeKeyReference>& ref2)
	{
		if(ref1->timestamp()>ref2->timestamp())
			return -1;
		if(ref1->timestamp()<ref2->timestamp())
			return 1;
		return 0;
	}
	//Compare names by timestamp
	int compareNamesByTimestamp(const os::smart_ptr<nodeNameReference>& ref1, const os::smart_ptr<nodeNameReference>& ref2)
	{
		if(ref1->timestamp()>ref2->timestamp())
			return -1;
		if(ref1->timestamp()<ref2->timestamp())
			return 1;
		return 0;
	}
	//Preforms quicksort on keys by timestamp
	void nodeGroup::sortKeys()
	{
		sortedKeys=os::smart_ptr<os::smart_ptr<nodeKeyReference> >(new os::smart_ptr<nodeKeyReference>[keyList.size()],os::shared_type_array);
		unsigned int cnt=0;
		for(auto i=keyList.first();i;++i)
		{
			sortedKeys[cnt]=&i;
			++cnt;
		}
		os::pointerQuicksort(sortedKeys,cnt,&compareKeysByTimestamp);
	}
	//Preforms quicksort on names by timestamp
	void nodeGroup::sortNames()
	{
		sortedNames=os::smart_ptr<os::smart_ptr<nodeNameReference> >(new os::smart_ptr<nodeNameReference>[nameList.size()],os::shared_type_array);
		unsigned int cnt=0;
		for(auto i=nameList.first();i;++i)
		{
			sortedNames[cnt]=&i;
			++cnt;
		}
		os::pointerQuicksort(sortedNames,cnt,&compareNamesByTimestamp);
	}

	//Return list of name nodes by timestamp
	os::smart_ptr<os::smart_ptr<nodeNameReference> > nodeGroup::namesByTimestamp(unsigned int& size)
	{
		sortingLock.lock();
		size=(unsigned)nameList.size();
		os::smart_ptr<os::smart_ptr<nodeNameReference> > ret=sortedNames;
		sortingLock.unlock();
		return ret;
	}
	//Return list of key nodes by timestamp
	os::smart_ptr<os::smart_ptr<nodeKeyReference> > nodeGroup::keysByTimestamp(unsigned int& size)
	{
		sortingLock.lock();
		size=(unsigned)keyList.size();
		os::smart_ptr<os::smart_ptr<nodeKeyReference> > ret=sortedKeys;
		sortingLock.unlock();
		return ret;
	}

    //Builds XML tree
    os::smart_ptr<os::XMLNode> nodeGroup::buildXML()
    {
        os::smart_ptr<os::XMLNode> ret(new os::XMLNode("nodeGroup"),os::shared_type);

        //Name list
        os::smart_ptr<os::XMLNode> tlevel(new os::XMLNode("names"),os::shared_type);
        for(auto i=nameList.first();i;++i)
        {
            os::smart_ptr<os::XMLNode> nlev(new os::XMLNode("name"),os::shared_type);

            //Group
            os::smart_ptr<os::XMLNode> temp(new os::XMLNode("group"),os::shared_type);
            temp->setData(i->groupName());
            nlev->addChild(*temp);

            //Name
            temp=os::smart_ptr<os::XMLNode>(new os::XMLNode("name"),os::shared_type);
            temp->setData(i->name());
            nlev->addChild(*temp);

            //Timestamp
            temp=os::smart_ptr<os::XMLNode>(new os::XMLNode("timestamp"),os::shared_type);
            temp->setData(std::to_string((long long unsigned int)i->timestamp()));
            nlev->addChild(*temp);

            tlevel->addChild(*nlev);
        }
        ret->addChild(*tlevel);

        //Key list
        tlevel=os::smart_ptr<os::XMLNode>(new os::XMLNode("keys"),os::shared_type);
        for(auto i=keyList.first();i;++i)
        {
            os::smart_ptr<os::XMLNode> klev(new os::XMLNode("key"),os::shared_type);

            //Key
            os::smart_ptr<os::XMLNode> temp(new os::XMLNode("key"),os::shared_type);
            for(unsigned t=0;t<i->keySize();t++)
                temp->addData(std::to_string((long long unsigned int)(*i->key())[t]));
            klev->addChild(*temp);

            //Key size
            temp=os::smart_ptr<os::XMLNode>(new os::XMLNode("keySize"),os::shared_type);
            temp->setData(std::to_string((long long unsigned int)i->keySize()*32));
            klev->addChild(*temp);

            //Algorithm
            temp=os::smart_ptr<os::XMLNode>(new os::XMLNode("algo"),os::shared_type);
			os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(i->algoID());
			if(!pkfrm) pkfrm=publicKeyTypeBank::singleton()->defaultPackage();
			temp->setData(pkfrm->algorithmName());
            klev->addChild(*temp);

            //Timestamp
            temp=os::smart_ptr<os::XMLNode>(new os::XMLNode("timestamp"),os::shared_type);
            temp->setData(std::to_string((long long unsigned int)i->timestamp()));
            klev->addChild(*temp);

            tlevel->addChild(*klev);
        }

        ret->addChild(*tlevel);

        return ret;
    }

/*-----------------------------------
    Node Name Reference
  -----------------------------------*/

    //Name reference constructor
    nodeNameReference::nodeNameReference(nodeGroup* master,std::string groupName,std::string name,uint64_t timestamp)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
		if(groupName.size()>size::GROUP_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);
		if(name.size()>size::NAME_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);

        _master=master;
        _groupName=groupName;
        _name=name;
        _timestamp=timestamp;
    }
    //Designed for searching
	nodeNameReference::nodeNameReference(std::string groupName,std::string name)
	{
		_master=NULL;
        _groupName=groupName;
        _name=name;
        _timestamp=os::getTimestamp();
	}
	//Use group name and name to compare
    int nodeNameReference::compare(const nodeNameReference& comp)const
    {
        int compV=_groupName.compare(comp._groupName);
        if(compV!=0) return compV;

        return _name.compare(comp._name);
    }

/*-----------------------------------
     Node Key Reference
-----------------------------------*/

    //Name reference constructor
    nodeKeyReference::nodeKeyReference(nodeGroup* master,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize,uint64_t timestamp)
    {
        if(!master) throw errorPointer(new NULLMaster(),os::shared_type);
        if(!key) throw errorPointer(new NULLPublicKey(),os::shared_type);

        _master=master;
        _key=key;
        _algoID=algoID;
        _keySize=keySize;
        _timestamp=timestamp;
    }
    //Designed for seraching
	nodeKeyReference::nodeKeyReference(os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
	{
		if(!key) throw errorPointer(new NULLPublicKey(),os::shared_type);

		_master=NULL;
        _key=key;
        _algoID=algoID;
        _keySize=keySize;
        _timestamp=os::getTimestamp();
	}
	//Use group name and name to compare
    int nodeKeyReference::compare(const nodeKeyReference& comp)const
    {
        int dif = _algoID-comp._algoID;
        if(dif!=0) return dif;
        dif = _keySize-comp._keySize;
        if(dif!=0) return dif;
        return _key->compare(comp._key.get());
    }

/*-----------------------------------
	Key Bank
-----------------------------------*/

	//Key bank constructor
	keyBank::keyBank(std::string savePath,const unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> strmPck)
	{
		_savePath=savePath;

		//Check key size
		if(keyLen>size::STREAM_SEED_MAX)
		{
			logError(errorPointer(new passwordLargeError(),os::shared_type));
			keyLen=size::STREAM_SEED_MAX;
		}

		//Copy key
		if(key==NULL || keyLen==0)
		{
			_symKey=NULL;
			_keyLen=0;
		}
		else
		{
			_symKey=new unsigned char[keyLen];
			memcpy(_symKey,key,keyLen);
			_keyLen=keyLen;
		}

		//Stream package
		_streamPackage=strmPck;
		if(_streamPackage)
			_streamPackage=streamPackageTypeBank::singleton()->defaultPackage();
		markChanged();
	}
	//Construct with public key
    keyBank::keyBank(std::string savePath,os::smart_ptr<publicKey> pubKey,os::smart_ptr<streamPackageFrame> strmPck)
	{
		_savePath=savePath;
		_symKey=NULL;
		_keyLen=0;
		_pubKey=pubKey;
		_streamPackage=strmPck;
		if(_streamPackage)
			_streamPackage=streamPackageTypeBank::singleton()->defaultPackage();
		markChanged();
	}
	//Set password
	void keyBank::setPassword(const unsigned char* key,size_t keyLen)
	{
		//Set key
		if(_symKey!=NULL)
			delete [] _symKey;

		//Check key size
		if(keyLen>size::STREAM_SEED_MAX)
		{
			logError(errorPointer(new passwordLargeError(),os::shared_type));
			keyLen=size::STREAM_SEED_MAX;
		}

		//Copy key
		if(key==NULL || keyLen==0)
		{
			_symKey=NULL;
			_keyLen=0;
		}
		else
		{
			_symKey=new unsigned char[keyLen];
			memcpy(_symKey,key,keyLen);
			_keyLen=keyLen;
		}

		markChanged();
	}
	//Set stream package
	void keyBank::setStreamPackage(os::smart_ptr<streamPackageFrame> strmPack)
	{
		_streamPackage=strmPack;
		if(_streamPackage)
			_streamPackage=streamPackageTypeBank::singleton()->defaultPackage();
		markChanged();
	}

	//Sets the public key
	void keyBank::setPublicKey(os::smart_ptr<publicKey> pubKey)
	{
		if(_pubKey && _pubKey!=pubKey)
			_pubKey->keyChangeSender::removeReceivers(this);
		_pubKey=pubKey;
		if(_pubKey)
			_pubKey->keyChangeSender::pushReceivers(this);
		markChanged();
	}
	//Triggers when the public key changes
	void keyBank::publicKeyChanged(os::smart_ptr<publicKey> pbk)
	{
		if(pbk==_pubKey)
			markChanged();
	}

/*-----------------------------------
     AVL Key Bank
-----------------------------------*/

    //AVL bank constructor
    avlKeyBank::avlKeyBank(std::string savePath,const unsigned char* key,size_t keyLen,os::smart_ptr<streamPackageFrame> strmPck):
        keyBank(savePath,key,keyLen,strmPck)
    {
        load();
    }
	avlKeyBank::avlKeyBank(std::string savePath,os::smart_ptr<publicKey> pubKey,os::smart_ptr<streamPackageFrame> strmPck):
		keyBank(savePath,pubKey,strmPck)
	{
		load();
	}
    //Load file
    void avlKeyBank::load()
    {
		if(savePath()=="") return;
		try
		{
			os::smart_ptr<os::XMLNode> headNode;
			errorPointer tempE;
			//First, try public key
			if(_pubKey)
			{
				try{headNode=EXML_Input(savePath(),_symKey,_keyLen);}
				catch (errorPointer e)
				{
					tempE=e;
					headNode=NULL;
				}
				catch (...) {throw errorPointer(new unknownErrorType(),os::shared_type);}
			}

			//Symetric key attempt
			try
			{
				//Have a public key
				if(_pubKey && !_pubKey->generating())
                    headNode=EXML_Input(savePath(),_pubKey);
				//Have a symetric key
				if(!headNode && _symKey!=NULL&&_keyLen>0)
                    headNode=EXML_Input(savePath(),_symKey,_keyLen);
				//No encryption
                if(!headNode)
                    headNode=os::smart_ptr<os::XMLNode>(new os::XMLNode(os::XMLNode::read(savePath())),os::shared_type);
			}
			catch (errorPointer e)
			{
				if(tempE) throw tempE;
				throw e;
			}
			catch (...)
			{
				if(tempE) throw tempE;
				throw errorPointer(new unknownErrorType(),os::shared_type);
			}

			if(!headNode)
				throw errorPointer(new fileOpenError(),os::shared_type);
			if(headNode->id()!="keyBank")
				throw errorPointer(new fileFormatError(),os::shared_type);

			//Iterate through children
			auto it=headNode->first();
			while(it)
			{
				os::smart_ptr<nodeGroup> nd=fileLoadHelper(&it);
				nodeBank.insert(nd);
				++it;
			}
		}
		catch (errorPointer e) {logError(e);}
		catch (...) {logError(errorPointer(new unknownErrorType(),os::shared_type));}
    }
    //Save file
    void avlKeyBank::save()
    {
		if(savePath()=="")
		{
			errorSaving("No saving path");
			return;
		}
		try
		{
            os::smart_ptr<os::XMLNode> headNode(new os::XMLNode("keyBank"),os::shared_type);
            for(auto i=nodeBank.first();i;++i)
				headNode->addChild(*i->buildXML());

			//Use public key first
			if(_pubKey && !_pubKey->generating())
			{
				if(!EXML_Output(savePath(),headNode,_pubKey,file::DOUBLE_LOCK,_streamPackage))
					throw errorPointer(new fileOpenError(),os::shared_type);
			}
			//Have a symetric key
			else if(_symKey!=NULL&&_keyLen>0)
			{
				if(!EXML_Output(savePath(),headNode,_symKey,_keyLen,_streamPackage))
					throw errorPointer(new fileOpenError(),os::shared_type);
			}
			//No encryption
			else
			{
                if(!os::XMLNode::write(savePath(), *headNode))
					throw errorPointer(new fileOpenError(),os::shared_type);
			}
		}
		catch (errorPointer e)
		{
			logError(e);
			errorSaving(e->errorTitle());
			return;
		}
		catch (...)
		{
			logError(errorPointer(new unknownErrorType(),os::shared_type));
			errorSaving("Unknown error");
			return;
		}
		finishedSaving();
    }

    //Push node (name)
    void avlKeyBank::pushNewNode(os::smart_ptr<nodeNameReference> name)
	{
		nameTree.insert(name);
		markChanged();
	}
    //Push node (key)
    void avlKeyBank::pushNewNode(os::smart_ptr<nodeKeyReference> key)
	{
		keyTree.insert(key);
		markChanged();
	}

    //Add authenticated node
    os::smart_ptr<nodeGroup> avlKeyBank::addPair(std::string groupName,std::string name,os::smart_ptr<number> key,uint16_t algoID,uint16_t keySize)
    {
        os::smart_ptr<nodeGroup> foundName=avlKeyBank::find(groupName,name);
        os::smart_ptr<nodeGroup> foundKey=avlKeyBank::find(key,algoID,keySize);

        os::smart_ptr<nodeGroup> ret;
        //Neither case
        if(!foundName && !foundKey)
        {
            ret=os::smart_ptr<nodeGroup>(new nodeGroup(this,groupName,name,key,algoID,keySize),os::shared_type);
            nodeBank.insert(ret);
        }
        //Only found the key
        else if(!foundName && foundKey)
        {
            foundKey->addAlias(groupName,name);
            ret=foundKey;
        }
        //Only found the name
        else if(foundName && !foundKey)
        {
            foundName->addKey(key,algoID,keySize);
            ret=foundName;
        }
        //Both name and key were found, but are seperate
        else if(foundName!=foundKey)
        {
            nodeBank.remove(foundKey);
            foundName->merge(*foundKey);
            ret=foundName;
        }
        //Name and key are the same
        else ret=foundName;
		markChanged();
        return ret;
    }
    //Find node (name)
    os::smart_ptr<nodeGroup> avlKeyBank::find(os::smart_ptr<nodeNameReference> name)
    {
        auto temp=nameTree.search(name);
        if(!temp) return os::smart_ptr<nodeGroup>();
        nodeGroup* ref=temp->master();
        if(!ref) return os::smart_ptr<nodeGroup>();

        auto trc = nodeBank.search(ref);
        if(!trc) return os::smart_ptr<nodeGroup>();
        return &trc;
    }
    //Fine node (key)
    os::smart_ptr<nodeGroup> avlKeyBank::find(os::smart_ptr<nodeKeyReference> key)
    {
        auto temp=keyTree.search(key);
        if(!temp) return os::smart_ptr<nodeGroup>();
        nodeGroup* ref=temp->master();
        if(!ref) return os::smart_ptr<nodeGroup>();

        auto trc = nodeBank.search(ref);
        if(!trc) return os::smart_ptr<nodeGroup>();
        return &trc;
    }
}

#endif

///@endcond
