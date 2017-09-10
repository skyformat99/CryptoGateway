/**
 * Implements the gateway
 * defined in gateway.h.  Consult
 * gateway.h for details.
 *
 */

///@cond INTERNAL

#ifndef GATEWAY_CPP
#define GATEWAY_CPP

#include "gateway.h"
#include "cryptoError.h"
#include "user.h"

namespace crypto {

	//Constructs the settings from user
	gatewaySettings::gatewaySettings(os::smart_ptr<user> usr, std::string groupID, std::string filePath)
	{
		if(!usr)
			throw errorPointer(new NULLPublicKey(),os::shared_type);
		_user=usr;

		_nodeName=usr->username();
		if(_groupID.size()>size::GROUP_SIZE)
			throw errorPointer(new stringTooLarge(),os::shared_type);
		_groupID=groupID;
		_filePath=filePath;

		_privateKey=_user->getDefaultPublicKey();
		if(!_privateKey)
			throw errorPointer(new NULLPublicKey(),os::shared_type);
		_privateKey->os::eventSender<keyChangeReceiver>::pushReceivers(this);
		_prefferedPublicKeyAlgo=_privateKey->algorithm();
		_prefferedPublicKeySize=_privateKey->size();

		update();
		markChanged();
	}
	//Destructor
	gatewaySettings::~gatewaySettings() throw()
	{
	}
	//Generate the XML save tree
	os::smart_ptr<os::XMLNode> gatewaySettings::generateSaveTree()
	{
        os::smart_ptr<os::XMLNode> ret(new os::XMLNode("gatewaySettings"),os::shared_type);

		os::smart_ptr<os::XMLNode> level1(new os::XMLNode("group"),os::shared_type);
		level1->setData(_groupID);
		ret->addChild(*level1);

		level1=os::smart_ptr<os::XMLNode>(new os::XMLNode("name"),os::shared_type);
		level1->setData(_nodeName);
		ret->addChild(*level1);

		level1=os::smart_ptr<os::XMLNode>(new os::XMLNode("preferences"),os::shared_type);

			os::smart_ptr<os::XMLNode> level2=os::smart_ptr<os::XMLNode>(new os::XMLNode("publicKey"),os::shared_type);
				os::smart_ptr<os::XMLNode> level3=os::smart_ptr<os::XMLNode>(new os::XMLNode("algo"),os::shared_type);
				level3->setData(std::to_string((long long unsigned int)_prefferedPublicKeyAlgo));
				level2->addChild(*level3);
				level3=os::smart_ptr<os::XMLNode>(new os::XMLNode("size"),os::shared_type);
				level3->setData(std::to_string((long long unsigned int)_prefferedPublicKeySize));
				level2->addChild(*level3);
			level1->addChild(*level2);

			level2=os::smart_ptr<os::XMLNode>(new os::XMLNode("hash"),os::shared_type);
				level3=os::smart_ptr<os::XMLNode>(new os::XMLNode("algo"),os::shared_type);
				level3->setData(std::to_string((long long unsigned int)_prefferedHashAlgo));
				level2->addChild(*level3);
				level3=os::smart_ptr<os::XMLNode>(new os::XMLNode("size"),os::shared_type);
				level3->setData(std::to_string((long long unsigned int)_prefferedHashSize));
				level2->addChild(*level3);
			level1->addChild(*level2);

			level2=os::smart_ptr<os::XMLNode>(new os::XMLNode("stream"),os::shared_type);
				level3=os::smart_ptr<os::XMLNode>(new os::XMLNode("algo"),os::shared_type);
				level3->setData(std::to_string((long long unsigned int)_prefferedStreamAlgo));
				level2->addChild(*level3);
			level1->addChild(*level2);

		ret->addChild(*level1);

		return ret;
	}
	//Triggered when the public key changes
	void gatewaySettings::publicKeyChanged(os::smart_ptr<publicKey> pbk)
	{
		if(!pbk) return;
		_privateKey=pbk;
		update();
	}
	//Update from user
	void gatewaySettings::update()
	{
		if(!_user) return;

		lock.lock();

		os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(_prefferedPublicKeyAlgo);
		os::smart_ptr<publicKey> tpbk;
		if(pkfrm)
		{
			pkfrm=pkfrm->getCopy();
			pkfrm->setKeySize(_prefferedPublicKeySize);
			tpbk=_user->findPublicKey(pkfrm);
			if(tpbk && !tpbk->getN()) tpbk=NULL;
		}

		//Only bind if the size is valid
		if(tpbk)
		{
			_privateKey=tpbk;
			_publicKey=_privateKey->getN();
			_publicKey->reduce();
		}
		else
		{
			_prefferedPublicKeyAlgo=_privateKey->algorithm();
			_prefferedPublicKeySize=_privateKey->size();
		}

		os::smart_ptr<streamPackageFrame> stmpkg=_user->streamPackage();
		_prefferedHashAlgo=stmpkg->hashAlgorithm();
		_prefferedHashSize=stmpkg->hashSize();
		_prefferedStreamAlgo=stmpkg->streamAlgorithm();

		lock.unlock();
	}
	//Save to file
	void gatewaySettings::save()
	{
		//Don't save if there isn't a path
		if(_filePath=="")
		{
			finishedSaving();
			return;
		}
		os::smart_ptr<os::XMLNode> nd=generateSaveTree();
        os::XMLNode::write(_filePath,*nd);
		finishedSaving();
	}
	//Loads gateway settings from file
	void gatewaySettings::load()
	{
		if(_filePath=="") return;

		update();
	}

	//Construct the settings from a ping message
	gatewaySettings::gatewaySettings(const message& msg)
	{
		//Parse ping message
		if(msg.data()[0]!=message::PING)
			throw errorPointer(new customError("Non-ping Intialization",
				"Attempted to initialize gateway settings with an non-ping message"),os::shared_type);

		//Pull out group ID and node name
		uint16_t msgCount=2;

		char* arr;
		if(size::GROUP_SIZE>size::NAME_SIZE)
		{
			arr=new char[size::GROUP_SIZE+1];
			memset(arr,0,size::GROUP_SIZE+1);
		}
		else
		{
			arr=new char[size::NAME_SIZE+1];
			memset(arr,0,size::NAME_SIZE+1);
		}

		memcpy(arr,msg.data()+msgCount,size::GROUP_SIZE);
		msgCount+=size::GROUP_SIZE;
		_groupID=std::string(arr);
		memcpy(arr,msg.data()+msgCount,size::NAME_SIZE);
		msgCount+=size::NAME_SIZE;
		_nodeName=std::string(arr);
		delete [] arr;

		//Extract preffered record
		uint16_t temp;
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedPublicKeyAlgo=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedPublicKeySize=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedHashAlgo=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedHashSize=os::from_comp_mode(temp);
		memcpy(&temp,msg.data()+msgCount,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		_prefferedStreamAlgo=os::from_comp_mode(temp);

		//Extract key
		os::smart_ptr<publicKeyPackageFrame> pkfrm=publicKeyTypeBank::singleton()->findPublicKey(_prefferedPublicKeyAlgo);
		if(pkfrm)
		{
			pkfrm=pkfrm->getCopy();
			pkfrm->setKeySize(_prefferedPublicKeySize);
			_publicKey=pkfrm->convert(msg.data()+msgCount,_prefferedPublicKeySize*sizeof(uint32_t));
		}
		msgCount+=_prefferedPublicKeySize*sizeof(uint32_t);
	}
	//Constructs a ping message
	os::smart_ptr<message> gatewaySettings::ping()
	{
		if(!_publicKey) return NULL;
		lock.increment();

		size_t msgCount=0;
		size_t keylen;
		os::smart_ptr<unsigned char> keyDat=_publicKey->getCompCharData(keylen);
		os::smart_ptr<message> png(new message((uint16_t) (2+size::GROUP_SIZE+size::NAME_SIZE+5*sizeof(uint16_t)+keylen)),os::shared_type);
		png->data()[0]=message::PING;
		png->data()[1]=gateway::UNKNOWN_BROTHER;
		msgCount+=2;

		//Copy in group ID and name
		memcpy(png->data()+msgCount,_groupID.c_str(),_groupID.size());
		msgCount+=size::GROUP_SIZE;
		memcpy(png->data()+msgCount,_nodeName.c_str(),_nodeName.size());
		msgCount+=size::NAME_SIZE;

		//Prefered record
		uint16_t temp;
		temp=os::to_comp_mode(_prefferedPublicKeyAlgo);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedPublicKeySize);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedHashAlgo);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedHashSize);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);
		temp=os::to_comp_mode(_prefferedStreamAlgo);
		memcpy(png->data()+msgCount,&temp,sizeof(uint16_t));
		msgCount+=sizeof(uint16_t);

		//Output key
		memcpy(png->data()+msgCount,keyDat.get(),keylen);
		msgCount+=keylen;

		//Is technically encrypted, has no message size
		png->_encryptionDepth=1;
		png->_messageSize=0;

		lock.decrement();

		return png;
	}

/*---------------------------------------
	Gateway
---------------------------------------*/

	//Construct the gateway
    gateway::gateway(os::smart_ptr<user> usr,std::string groupID)
	{
		if(!usr)
			throw errorPointer(new keyMissing(), os::shared_type);
		selfSettings=usr->insertSettings(groupID);
		if(!selfSettings)
			throw errorPointer(new keyMissing(), os::shared_type);

		_currentState=UNKNOWN_BROTHER;
		_brotherState=UNKNOWN_STATE;

		_lastError=NULL;
		_lastErrorLevel=BASIC_ERROR_STATE;

		_timeout=DEFAULT_TIMEOUT;
		_safeTimeout=3*_timeout/4;
		_errorTimeout=DEFAULT_ERROR_TIMEOUT;
		_messageReceived=0;
		_messageSent=0;
		_errorTimestamp=0;

		clearStream();
	}

	//Builds the next message based on state
	os::smart_ptr<message> gateway::getMessage()
	{
		os::smart_ptr<message> ret;
		processTimestamps();

		switch(_currentState)
		{
		//Process for the unknown state
		case UNKNOWN_STATE:
			_currentState=UNKNOWN_BROTHER;
		//As long as we don't know our brother, send out pings
		case UNKNOWN_BROTHER:
		case SETTINGS_EXCHANGED:
			ret=ping();
			if(!ret)
			{
				ret=currentError();
				if(!ret) return NULL;
				break;
			}

		//Bind self settings
            selfSettings->lock.increment();
			lock.acquire();
			selfStream=streamPackageTypeBank::singleton()->findStream(selfSettings->prefferedStreamAlgo(),selfSettings->prefferedHashAlgo());
			selfPKFrame=publicKeyTypeBank::singleton()->findPublicKey(selfSettings->prefferedPublicKeyAlgo());
			selfPublicKey=selfSettings->getPrivateKey();

			if(!selfStream || !selfPKFrame)
			{
				lock.release();
                selfSettings->lock.decrement();
				logError(errorPointer(new illegalAlgorithmBind("ILLEGAL ALGO"),os::shared_type));
				ret=currentError();
				break;
			}
			selfStream=selfStream->getCopy();
			selfPKFrame=selfPKFrame->getCopy();
			selfStream->setHashSize(selfSettings->prefferedHashSize());
			selfPKFrame->setKeySize(selfSettings->prefferedPublicKeySize());
			lock.release();
            selfSettings->lock.decrement();

			break;
		//Until we are signing, establish the stream
		case ESTABLISHING_STREAM:
		case STREAM_ESTABLISHED:
			buildStream();
			if(!streamMessageOut)
			{
				ret=currentError();
				break;
			}
			streamMessageOut->data()[1]=_currentState;
			ret=streamMessageOut;

			break;

		//Attempt to sign
		case SIGNING_STATE:
		case CONFIRM_OLD:
		{
			lock.acquire();
			uint64_t curstamp=os::getTimestamp();
			uint64_t primaryStamp,secondaryStamp;

			os::smart_ptr<user> self=selfSettings->getUser();
			if(!brotherPublicKey || !brotherPKFrame || !brotherStream)
			{
				lock.release();
				logError(errorPointer(new customError("Brother Undefined","Cannot build stream when the brother is undefined"),os::shared_type));
				ret=currentError();
				break;
			}
			if(!self || !self->getKeyBank())
			{
				lock.release();
				logError(errorPointer(new customError("Self Not Found","The gateway could not find itself"),os::shared_type));
				ret=currentError();
				break;
			}

			//Try and find old keys
			os::smart_ptr<nodeGroup> bgr=self->getKeyBank()->find(brotherSettings->groupID(),brotherSettings->nodeName());
			os::smart_ptr<os::smart_ptr<nodeKeyReference> > keyList;
			os::smart_ptr<unsigned char> hashArray;
			unsigned int listSize;
			if(bgr)
			{
				keyList=bgr->keysByTimestamp(listSize);
				if(listSize!=0)
				{
					if(listSize>5) listSize=5;
					hashArray=os::smart_ptr<unsigned char>(new unsigned char[listSize*brotherStream->hashSize()],os::shared_type_array);
					for(unsigned int i=0;hashArray&&i<listSize;++i)
					{
						if(*brotherPublicKey==*keyList[i]->key())
							hashArray=NULL;
						else
						{
							size_t hashLen;
							os::smart_ptr<unsigned char> dat=keyList[i]->key()->getCompCharData(hashLen);
							hash hsh=brotherStream->hashData(dat.get(),hashLen);
							memcpy(hashArray.get()+i*brotherStream->hashSize(),hsh.data(),hsh.size());
						}
					}
				}
			}
			if(!hashArray) listSize=0;

			//Search for old keys based on input hashes
			uint16_t secondaryKeySize=0;
			size_t chrData;
			os::smart_ptr<number> oldPK;
			os::smart_ptr<publicKey> oldPKSignTarg;
			os::smart_ptr<uint8_t> dat=selfPreciseKey->getCompCharData(chrData);
			hash cpub=selfStream->hashData(dat.get(),chrData);
			size_t secondaryHistory=~0;

			//At this point, we know our brother does not know our current public key
			if(eligibleKeys.size()>0 && !eligibleKeys.find(&cpub))
			{
				bool type;
				for(auto htrc=eligibleKeys.first();htrc && !oldPKSignTarg;++htrc)
				{
					oldPKSignTarg=selfSettings->getUser()->searchKey(*htrc,secondaryHistory,type);
				}

				if(oldPKSignTarg) oldPK=oldPKSignTarg->getOldN(secondaryHistory);
				if(!oldPKSignTarg || !oldPK)
				{
					lock.release();
					logError(errorPointer(new customError("Old Key Not Found","Old keys, as listed by the node's brother, could not be found"),os::shared_type),TIMEOUT_ERROR_STATE);
					ret=currentError();
					break;
				}
				secondaryKeySize=oldPKSignTarg->size();
			}


			//Build output
			ret=os::smart_ptr<message>(new message(2+16+selfPKFrame->keySize()*4+2+secondaryKeySize*4+1+(1+listSize)*brotherStream->hashSize()),os::shared_type);
			ret->data()[0]=message::SIGNING_MESSAGE;
			ret->data()[1]=_currentState;

			//Timestamps first
			bool prim,sec;
			if(selfSigningMessage)
			{
				memcpy(&primaryStamp,selfSigningMessage->data()+2,8);
				primaryStamp=os::from_comp_mode(primaryStamp);
				memcpy(&secondaryStamp,selfSigningMessage->data()+10,8);
				secondaryStamp=os::from_comp_mode(secondaryStamp);
				prim=false;
				sec=false;
			}
			else
			{
				primaryStamp=curstamp;
				secondaryStamp=curstamp;
				prim=true;
				sec=true;
			}
			if(curstamp>primaryStamp+_safeTimeout)
			{
				primaryStamp=curstamp;
				prim=true;
			}
			if(curstamp>secondaryStamp+_safeTimeout)
			{
				secondaryStamp=curstamp;
				sec=true;
			}

			//Catch weird edge case
			if(!outputHashArray)
			{
				lock.release();
				logError(errorPointer(new customError("Init Error","Stream failed to build before hashing data"),os::shared_type));
				ret=currentError();
				break;
			}

			//Primary hash
			primaryStamp=os::to_comp_mode(primaryStamp);
			memcpy(ret->data()+2,&primaryStamp,8);
			memcpy(outputHashArray.get(),&primaryStamp,8);
			hash temp=selfStream->hashData(outputHashArray.get(),outputHashLength);
			if(!selfPrimarySignatureHash || temp!=*selfPrimarySignatureHash) prim=true;
			if(prim)
			{
				selfPrimarySignatureHash=os::smart_ptr<hash>(new hash(temp),os::shared_type);
				os::smart_ptr<number> num;
				if(temp.size()>selfPKFrame->keySize()*4) num=selfPKFrame->convert(temp.data(),selfPKFrame->keySize()*4);
				else num=selfPKFrame->convert(temp.data(),temp.size());
				num->data()[selfPKFrame->keySize()-1]&=(~(uint32_t)0)>>6;

				size_t hist;
				bool typ;
				selfPublicKey->searchKey(selfPreciseKey,hist,typ);
				try
				{
					num=selfPublicKey->decode(num,hist);
				}
				catch(...){
                    num=NULL;
                }
				if(!num)
				{
					lock.release();
					logError(errorPointer(new customError("Could not Sign, Primary","Unexpected error occurred while attempting to sign a hash"),os::shared_type),TIMEOUT_ERROR_STATE);
					ret=currentError();
					break;
				}
				os::smart_ptr<unsigned char> tdat=num->getCompCharData(hist);
				memcpy(ret->data()+2+16,tdat.get(),selfPKFrame->keySize()*4);
			}

			//Secondary hash
			secondaryStamp=os::to_comp_mode(secondaryStamp);
			memcpy(ret->data()+2+8,&secondaryStamp,8);
			memcpy(outputHashArray.get(),&secondaryStamp,8);
			temp=selfStream->hashData(outputHashArray.get(),outputHashLength);
			if(!selfSecondarySignatureHash || temp!=*selfSecondarySignatureHash) sec=true;
			if(sec && eligibleKeys.size()<=0)  sec=false;
			if(sec && secondaryKeySize>0)
			{
				dat=oldPK->getCompCharData(chrData);
				cpub=brotherStream->hashData(dat.get(),chrData);

				selfSecondarySignatureHash=os::smart_ptr<hash>(new hash(temp),os::shared_type);
				os::smart_ptr<number> num;
				if(temp.size()>secondaryKeySize*4) num=oldPKSignTarg->copyConvert(temp.data(),secondaryKeySize-1);
				else num=oldPKSignTarg->copyConvert(temp.data(),temp.size());
				num->data()[secondaryKeySize-1]&=(~(uint32_t)0)>>6;

				try
				{
					num=oldPKSignTarg->decode(num,secondaryHistory);
				}
                catch(...){
                    num=NULL;
                }
				if(!num)
				{
					lock.release();
					logError(errorPointer(new customError("Could not Sign, Secondary","Unexpected error occurred while attempting to sign a hash"),os::shared_type),TIMEOUT_ERROR_STATE);
					ret=currentError();
					break;
				}

				memcpy(ret->data()+2+16+selfPKFrame->keySize()*4+2,cpub.data(),cpub.size());
				os::smart_ptr<unsigned char> tdat=num->getCompCharData(chrData);
				memcpy(ret->data()+2+16+selfPKFrame->keySize()*4+2+brotherStream->hashSize(),tdat.get(),secondaryKeySize*4);
			}

			//Valid hash list
			ret->data()[2+16+selfPKFrame->keySize()*4+2+secondaryKeySize*4+brotherStream->hashSize()]=listSize;
			if(listSize>0)
				memcpy(ret->data()+2+16+selfPKFrame->keySize()*4+2+secondaryKeySize*4+1+brotherStream->hashSize(),hashArray.get(),listSize*brotherStream->hashSize());

			//Bind secondary key size
			secondaryKeySize=os::to_comp_mode(secondaryKeySize);
			memcpy(ret->data()+2+16+selfPKFrame->keySize()*4,&secondaryKeySize,2);

			selfSigningMessage=os::smart_ptr<message>(new message(*ret),os::shared_type);
			lock.release();

			ret=encrypt(ret);
			if(!ret) ret=currentError();
		}
			break;

		//Secure exchange settings
		case ESTABLISHED:
			ret=os::smart_ptr<message>(new message(2+1),os::shared_type);
			ret->data()[0]=message::SECURE_DATA_EXCHANGE;
			ret->data()[1]=_currentState;
			ret->data()[2]=0;

			ret=encrypt(ret);
			if(!ret) ret=currentError();
			break;

		//Error State
		case BASIC_ERROR_STATE:
		case TIMEOUT_ERROR_STATE:
		case PERMENANT_ERROR_STATE:

			ret=currentError();
			break;

		//Confirm error state
		case CONFIRM_ERROR_STATE:
            clearStream();
			ret=os::smart_ptr<message>(new message(2),os::shared_type);
			ret->data()[0]=message::CONFIRM_ERROR;
			ret->data()[1]=_currentState;

			break;

		default:
			break;
		}

		//No message to return
		if(!ret)
		{
			logError(errorPointer(new customError("Message Undefined",
					"Current system state does not define a message to be returned"),os::shared_type));
			ret=currentError();
			if(!ret) return NULL;
		}

		stampLock.acquire();
		_messageSent=os::getTimestamp();
		stampLock.release();
		return ret;
	}
	//Send a message through the gateway
	os::smart_ptr<message> gateway::send(os::smart_ptr<message> msg)
	{
		msg=encrypt(msg);
		if(!msg) msg=currentError();

		//No message to return
		if(!msg)
		{
			logError(errorPointer(new customError("Message Undefined",
					"Current system state does not define a message to be returned"),os::shared_type));
			msg=currentError();
			if(!msg) return NULL;
		}

		//Timestamp out
		stampLock.acquire();
		_messageSent=os::getTimestamp();
		stampLock.release();
		return msg;
	}
	//Process message
	os::smart_ptr<message> gateway::processMessage(os::smart_ptr<message> msg)
	{
		//NULL message, exit
		if(!msg) return NULL;

		processTimestamps();

		stampLock.acquire();
		_messageReceived=os::getTimestamp();
		stampLock.release();

		uint8_t messageType=msg->data()[0];
		bool newMessage=false;
		uint16_t tempCnt1;
		uint16_t tempCnt2;

		char* tempChar1;
		char* tempChar2;

		switch(messageType)
		{
		//Process a ping message
		case message::PING:
			lock.acquire();
			if(_currentState!=UNKNOWN_STATE && _currentState!=UNKNOWN_BROTHER
				&& _currentState!=SETTINGS_EXCHANGED && _currentState!=CONFIRM_ERROR_STATE)
			{
				lock.release();
				logError(errorPointer(new customError("Ping Received Error","Current state could not receive a stream key"),os::shared_type));
				return NULL;
			}

			try
			{
				brotherSettings=os::smart_ptr<gatewaySettings>(new gatewaySettings(*msg),os::shared_type);
			}
			catch(errorPointer ep)
			{
				lock.release();
				logError(ep);
				return NULL;
			}
			catch(...)
			{
				lock.release();
				logError(errorPointer(new unknownErrorType(),os::shared_type));
				return NULL;
			}

			//Bind state and brother state
			_brotherState=msg->data()[1];
			if(_currentState==UNKNOWN_BROTHER || _currentState==SETTINGS_EXCHANGED || _currentState==CONFIRM_ERROR_STATE)
			{
				if(_brotherState==SETTINGS_EXCHANGED) _currentState=ESTABLISHING_STREAM;
				else _currentState=SETTINGS_EXCHANGED;
			}

		//Bind brother settings
			brotherStream=streamPackageTypeBank::singleton()->findStream(brotherSettings->prefferedStreamAlgo(),brotherSettings->prefferedHashAlgo());
			brotherPKFrame=publicKeyTypeBank::singleton()->findPublicKey(brotherSettings->prefferedPublicKeyAlgo());
			brotherPublicKey=brotherSettings->getPublicKey();
			if(!brotherStream || !brotherPKFrame)
			{
				lock.release();
				logError(errorPointer(new illegalAlgorithmBind("ILLEGAL ALGO"),os::shared_type));
				return NULL;
			}
			brotherStream=brotherStream->getCopy();
			brotherPKFrame=brotherPKFrame->getCopy();
			brotherStream->setHashSize(brotherSettings->prefferedHashSize());
			brotherPKFrame->setKeySize(brotherSettings->prefferedPublicKeySize());
			lock.release();

			break;

		//Process a stream message
		case message::STREAM_KEY:
			lock.acquire();

			//Bind state and brother state
			_brotherState=msg->data()[1];
			if(_currentState==SETTINGS_EXCHANGED ||
				_currentState==ESTABLISHING_STREAM || _currentState==STREAM_ESTABLISHED ||
				_currentState==SIGNING_STATE)
			{
				if(_brotherState==ESTABLISHING_STREAM) _currentState=STREAM_ESTABLISHED;
				else if(_brotherState==STREAM_ESTABLISHED) _currentState=SIGNING_STATE;
				else
				{
					lock.release();
					logError(errorPointer(new customError("Stream Received Error","Brother state could not send a stream key"),os::shared_type));
					return NULL;
				}
			}
			else
			{
				lock.release();
				logError(errorPointer(new customError("Stream Received Error","Current state cannot receive a stream key"),os::shared_type));
				return NULL;
			}

			//Process message
			if(!streamMessageIn) newMessage=true;
			else
			{
				newMessage=false;
				for(unsigned int i=2;i<msg->size() && !newMessage;++i)
				{
					if(msg->data()[i]!=streamMessageIn->data()[i])
						newMessage=true;
				}
			}
			if(newMessage)
			{
				streamMessageIn=msg;
				size_t keySize=msg->size()-2;
				uint8_t* strmKey=new uint8_t[keySize];
				memcpy(strmKey,streamMessageIn->data()+2,msg->size()-2);

				selfPublicKey->readLock();
				size_t hist;
				bool typ;
				selfPublicKey->searchKey(selfPreciseKey,hist,typ);
				selfPublicKey->decode(strmKey,keySize,hist);
				inputStream=os::smart_ptr<streamDecrypter>(new streamDecrypter(selfStream->buildStream(strmKey,keySize)),os::shared_type);
				selfPublicKey->readUnlock();

				inputHashLength=(uint16_t) (keySize+2*size::NAME_SIZE+2*size::GROUP_SIZE+8);
				inputHashArray=os::smart_ptr<uint8_t>(new uint8_t[inputHashLength],os::shared_type_array);
				memset(inputHashArray.get(),0,inputHashLength);
				memcpy(inputHashArray.get()+8,strmKey,keySize);
				memcpy(inputHashArray.get()+8+keySize,brotherSettings->groupID().c_str(),brotherSettings->groupID().length());
				memcpy(inputHashArray.get()+8+keySize+size::GROUP_SIZE,brotherSettings->nodeName().c_str(),brotherSettings->nodeName().length());

				memcpy(inputHashArray.get()+8+keySize+size::NAME_SIZE+size::GROUP_SIZE,selfSettings->groupID().c_str(),selfSettings->groupID().length());
				memcpy(inputHashArray.get()+8+keySize+size::NAME_SIZE+2*size::GROUP_SIZE,selfSettings->nodeName().c_str(),selfSettings->nodeName().length());

				delete [] strmKey;
			}
			lock.release();

			break;

		//Sign a message
		case message::SIGNING_MESSAGE:
		{
			if(_currentState==ESTABLISHED)
				return NULL;
			if(_currentState==STREAM_ESTABLISHED || _currentState==SIGNING_STATE || _currentState==CONFIRM_OLD)
				msg=decrypt(msg);
			else
			{
				logError(errorPointer(new customError("Signing Received Error","Current state cannot receive a signing message"),os::shared_type));
				return NULL;
			}
			if(!msg) return NULL;

			uint64_t tstamp=0;
			bool keyInRecord=false;

			lock.acquire();
			_brotherState=msg->data()[1];

			//Process primary key
			memcpy(&tstamp,msg->data()+2,8);
			memcpy(inputHashArray.get(),msg->data()+2,8);
			tstamp=os::from_comp_mode(tstamp);
			if(tstamp+_timeout<os::getTimestamp() || tstamp>os::getTimestamp()+_timeout)
			{
				lock.release();
				logError(errorPointer(new customError("Invalid Timestamp","A crypto-graphic timestamp which was out of range was received"),os::shared_type),TIMEOUT_ERROR_STATE);
				return NULL;
			}
			hash tHash=brotherStream->hashData(inputHashArray.get(),inputHashLength);
			if(!brotherPrimarySignatureHash || tHash!=*brotherPrimarySignatureHash)
			{
				os::smart_ptr<number> num1;
				os::smart_ptr<number> num2=brotherPKFrame->convert(msg->data()+2+16,brotherPKFrame->keySize()*4);
				try
				{
					num2=brotherPKFrame->encode(num2,brotherPublicKey);
				}
				catch(...){num2=NULL;}

				if(tHash.size()>brotherPKFrame->keySize()*4) num1=brotherPKFrame->convert(tHash.data(),brotherPKFrame->keySize()*4);
				else num1=brotherPKFrame->convert(tHash.data(),tHash.size());
				num1->data()[brotherPKFrame->keySize()-1]&=(~(uint32_t)0)>>6;

				if(!num2 || *num1!=*num2)
				{
					lock.release();
                    logError(errorPointer(new customError("Signature Failure, Primary","The brother failed to sign the hash."),os::shared_type),TIMEOUT_ERROR_STATE);
					return NULL;
				}
				brotherPrimarySignatureHash=os::smart_ptr<hash>(new hash(tHash),os::shared_type);
			}

			//Find user, check if we already are checking a known public key
			os::smart_ptr<keyBank> bank=selfSettings->getUser()->getKeyBank();
			if(!bank)
			{
				lock.release();
				logError(errorPointer(new customError("No Key Bank Found","The user does not have a key bank"),os::shared_type));
				return NULL;
			}
			os::smart_ptr<nodeGroup> node=bank->find(brotherSettings->groupID(),brotherSettings->nodeName());
			if(node && node == bank->find(brotherPublicKey,brotherPKFrame->algorithm(),brotherPKFrame->keySize()))
				keyInRecord=true;

			//Process secondary key
			memcpy(&tstamp,msg->data()+2+8,8);
			memcpy(inputHashArray.get(),msg->data()+2+8,8);
			tstamp=os::from_comp_mode(tstamp);
			if(tstamp+_timeout<os::getTimestamp() || tstamp>os::getTimestamp()+_timeout)
			{
				lock.release();
				logError(errorPointer(new customError("Invalid Timestamp","A crypto-graphic timestamp which was out of range was received"),os::shared_type),TIMEOUT_ERROR_STATE);
				return NULL;
			}
			tHash=brotherStream->hashData(inputHashArray.get(),inputHashLength);
			uint16_t secondaryKeySize;
			memcpy(&secondaryKeySize,msg->data()+2+16+brotherPKFrame->keySize()*4,2);
			secondaryKeySize=os::from_comp_mode(secondaryKeySize);

			//Confirmed that we actually need to process the signature
			if(secondaryKeySize>0 && !keyInRecord && (!brotherSecondarySignatureHash || tHash!=*brotherSecondarySignatureHash))
			{
				hash secondKeyHsh=selfStream->hashCopy(msg->data()+2+16+brotherPKFrame->keySize()*4+2);

				//Try and find key
				unsigned int listSize;
				os::smart_ptr<os::smart_ptr<nodeKeyReference> > keyList=node->keysByTimestamp(listSize);
				os::smart_ptr<nodeKeyReference> secKey;
				for(unsigned int i=0;i<5 && i<listSize && !secKey;++i)
				{
					size_t datLen=0;
					auto tdat=keyList[i]->key()->getCompCharData(datLen);
					hash comp=selfStream->hashData(tdat.get(),datLen);
					if(comp==secondKeyHsh)
						secKey=keyList[i];
				}
				if(!secKey || secKey->keySize()!=secondaryKeySize)
				{
					lock.release();
					logError(errorPointer(new customError("Key Not Found","The key our brother used to establish identity is not recognized"),os::shared_type),TIMEOUT_ERROR_STATE);
					return NULL;
				}
				os::smart_ptr<publicKeyPackageFrame> secPKFrame= publicKeyTypeBank::singleton()->findPublicKey(secKey->algoID());
				if(!secPKFrame)
				{
					lock.release();
					logError(errorPointer(new customError("Algorithm Not Found","The key our brother used to establish identity uses an algorithm which is undefined"),os::shared_type),TIMEOUT_ERROR_STATE);
					return NULL;
				}
				secPKFrame=secPKFrame->getCopy();
				secPKFrame->setKeySize(secKey->keySize());

				//Preform signature
				os::smart_ptr<number> num1;
				os::smart_ptr<number> num2=secPKFrame->convert(msg->data()+2+16+brotherPKFrame->keySize()*4+2+selfStream->hashSize(),secPKFrame->keySize()*4);
				try
				{
					num2=secPKFrame->encode(num2,secKey->key());
				}
				catch(...){num2=NULL;}

				if(tHash.size()>secPKFrame->keySize()*4) num1=secPKFrame->convert(tHash.data(),secPKFrame->keySize()*4);
				else num1=secPKFrame->convert(tHash.data(),tHash.size());
				num1->data()[secPKFrame->keySize()-1]&=(~(uint32_t)0)>>6;

				if(!num2 || *num1!=*num2)
				{
					lock.release();
                    logError(errorPointer(new customError("Signature Failure Secondary","The brother failed to sign the hash."),os::shared_type),TIMEOUT_ERROR_STATE);
					return NULL;
				}
				brotherSecondarySignatureHash=os::smart_ptr<hash>(new hash(tHash),os::shared_type);
			}

			//Read in our possible hash targets
			uint8_t arrLen=msg->data()[2+16+brotherPKFrame->keySize()*4+2+secondaryKeySize*4+selfStream->hashSize()];
			eligibleKeys=os::pointerUnsortedList<hash>();
			for(unsigned int i=arrLen;i>0;i--)
			{
				eligibleKeys.insert(os::smart_ptr<hash>(
					new hash(selfStream->hashCopy(msg->data()+2+16+brotherPKFrame->keySize()*4+2+secondaryKeySize*4+1+i*selfStream->hashSize())),os::shared_type));
			}

			//This case means the connection is authenticated
			if((node&&(brotherSecondarySignatureHash || keyInRecord)) || !node)
			{
				//Insert the pair (bank takes care of it!)
				node=bank->addPair(brotherSettings->groupID(),brotherSettings->nodeName(),brotherPublicKey,brotherPKFrame->algorithm(),brotherPKFrame->keySize());

				//Lastly, stream is established
				if(_brotherState==CONFIRM_OLD || _brotherState==ESTABLISHED) _currentState=ESTABLISHED;
				else _currentState=CONFIRM_OLD;
			}
			//Otherwise, let your brother know you need to match an old key
			else
				_currentState=CONFIRM_OLD;

			lock.release();
		}
			break;

		//Settings exchange
		case message::SECURE_DATA_EXCHANGE:
			if(_currentState!=ESTABLISHED && _currentState!=CONFIRM_OLD)
			{
				logError(errorPointer(new customError("Invalid State","Cannot receive a data-exchange message when not secured"),os::shared_type));
				return NULL;
			}

			msg=decrypt(msg);
			if(!msg) return NULL;

			_brotherState=msg->data()[1];
			if(_brotherState!=ESTABLISHED)
			{
				logError(errorPointer(new customError("Invalid Brother State","Cannot send a data-exchange message when not secured"),os::shared_type));
				return NULL;
			}
			if(_currentState==CONFIRM_OLD)
				_currentState=ESTABLISHED;


			//No parsing a settings exchange yet

			break;

		//Error message
		case message::BASIC_ERROR:
		case message::TIMEOUT_ERROR:
		case message::PERMENANT_ERROR:
			//Attempt to process
			lock.acquire();
			if(_brotherState==msg->data()[1])
			{
				lock.release();
				return msg;
			}
			_brotherState=msg->data()[1];
			_currentState=CONFIRM_ERROR_STATE;
			tempCnt1=2;
			lock.release();
			if(msg->size()==2) return msg;

			memcpy(&tempCnt2,msg->data()+tempCnt1,2);
			tempCnt2=os::from_comp_mode(tempCnt2);
			if(tempCnt2>msg->size())
			{
				logError(errorPointer(new bufferLargeError(),os::shared_type));
				return NULL;
			}
			tempChar1=new char[tempCnt2+1];
			memset(tempChar1,0,tempCnt2+1);
			tempCnt1+=2;
			memcpy(tempChar1,msg->data()+tempCnt1,tempCnt2);

			tempCnt1+=tempCnt2;
			memcpy(&tempCnt2,msg->data()+tempCnt1,2);
			tempCnt2=os::from_comp_mode(tempCnt2);
			if(tempCnt2>msg->size())
			{
				delete [] tempChar1;
				logError(errorPointer(new bufferLargeError(),os::shared_type));
				return NULL;
			}
			tempChar2=new char[tempCnt2+1];
			memset(tempChar2,0,tempCnt2+1);
			tempCnt1+=2;
			memcpy(tempChar2,msg->data()+tempCnt1,tempCnt2);
			errorSender::logError(errorPointer(new customError("BrotherError: "+std::string(tempChar1),std::string(tempChar2)),os::shared_type));

			delete [] tempChar1;
			delete [] tempChar2;

			break;

		//Confirm error
		case message::CONFIRM_ERROR:
			_brotherState=msg->data()[1];

			//Revert to unknown state
			if(_currentState!=TIMEOUT_ERROR_STATE &&
				_currentState!=PERMENANT_ERROR_STATE)
				_currentState=UNKNOWN_BROTHER;

			break;
		default:

			//Normal message case
			if(_currentState!=ESTABLISHED)
			{
				logError(errorPointer(new customError("Invalid State","Cannot receive a data-exchange message when not secured"),os::shared_type));
				return NULL;
			}
			msg=decrypt(msg);
			if(!msg) return NULL;

			break;
		}
		return msg;
	}
	//Ping message
	os::smart_ptr<message> gateway::ping()
	{
        selfSettings->lock.increment();
		selfSettings->getPrivateKey()->readLock();
		os::smart_ptr<message> ret=selfSettings->ping();
		if(!ret)
		{
            selfSettings->getPrivateKey()->readUnlock();
            selfSettings->lock.increment();
			logError(errorPointer(new customError("Ping Message Undefined",
				"Settings inside the gateway could not generate a ping message"),os::shared_type));
			return NULL;
		}
		ret->data()[1]=_currentState;
		selfPreciseKey=selfSettings->getPrivateKey()->getN();
		selfSettings->getPrivateKey()->readUnlock();
        selfSettings->lock.decrement();
		return ret;
	}
	//Process timestamp differences
	void gateway::processTimestamps()
	{
		stampLock.acquire();

		//Timeout errors
		if(_currentState==TIMEOUT_ERROR_STATE)
		{
			if(_errorTimestamp+_errorTimeout<os::getTimestamp())
			{
				lock.acquire();
				if(_brotherState==CONFIRM_ERROR_STATE)
					_currentState=UNKNOWN_BROTHER;
				else
					_currentState=BASIC_ERROR_STATE;
				lock.release();
			}
		}
		//All states that can timeout
		else if(_currentState!=PERMENANT_ERROR_STATE)
		{
			if(_messageReceived+_timeout<os::getTimestamp())
			{
				lock.acquire();
				_currentState=UNKNOWN_BROTHER;
				lock.release();
			}
		}


		stampLock.release();
	}

	//Returns a message about the current error
	os::smart_ptr<message> gateway::currentError()
	{
		if(_currentState!=BASIC_ERROR_STATE
			&& _currentState!=TIMEOUT_ERROR_STATE
			&& _currentState!=PERMENANT_ERROR_STATE)
			return NULL;

		os::smart_ptr<message> ret;
		lock.acquire();
		if(!_lastError)
		{
			lock.release();
			ret=os::smart_ptr<message>(new message(2),os::shared_type);
			ret->data()[0]=_lastErrorLevel;
			ret->data()[1]=_currentState;
			return ret;
		}
		ret=os::smart_ptr<message>(new message((uint16_t) (6+_lastError->errorTitle().length()+_lastError->errorDescription().length())),os::shared_type);
		ret->data()[0]=_lastErrorLevel;
		ret->data()[1]=_currentState;

		uint16_t tempCnt1=2;
		uint16_t tempCnt2=(uint16_t)_lastError->errorTitle().length();
		tempCnt2=os::to_comp_mode(tempCnt2);
		memcpy(ret->data()+tempCnt1,&tempCnt2,2);
		tempCnt1+=2;
		memcpy(ret->data()+tempCnt1,_lastError->errorTitle().c_str(),_lastError->errorTitle().length());

		tempCnt1+=(uint16_t)_lastError->errorTitle().length();
		tempCnt2=(uint16_t)_lastError->errorTitle().length();
		tempCnt2=os::to_comp_mode(tempCnt2);
		memcpy(ret->data()+tempCnt1,&tempCnt2,2);
		tempCnt1+=2;
		memcpy(ret->data()+tempCnt1,_lastError->errorDescription().c_str(),_lastError->errorDescription().length());

		lock.release();
		return ret;
	}
	//Returns brother data
	os::smart_ptr<nodeGroup> gateway::brotherNode()
	{
		os::smart_ptr<nodeGroup> ret;
		if(!secure()) return NULL;
		if(!brotherSettings) return NULL;
		ret=selfSettings->getUser()->getKeyBank()->find(brotherSettings->groupID(),brotherSettings->nodeName());
		return ret;
	}

//Private Functions-----------------------------------------------------------

	//Register error
	void gateway::logError(errorPointer elm,uint8_t errType)
	{
		//Bind error state
		lock.acquire();
		switch(errType)
		{
		case TIMEOUT_ERROR_STATE:
			if(_currentState!=PERMENANT_ERROR_STATE)
			{
				_lastError=elm;
				_currentState=TIMEOUT_ERROR_STATE;
			}
			break;
		case PERMENANT_ERROR_STATE:
			_currentState=PERMENANT_ERROR_STATE;
			_lastError=elm;
			break;
		default:
			if(_currentState!=PERMENANT_ERROR_STATE && _currentState!=TIMEOUT_ERROR_STATE)
			{
				_lastError=elm;
				_currentState=BASIC_ERROR_STATE;
			}
		}

		lock.release();

		stampLock.acquire();
		_errorTimestamp=os::getTimestamp();
		stampLock.release();

		clearStream();
		errorSender::logError(elm);
	}
	//Clear stream data
	void gateway::clearStream()
	{
		streamEstTimestamp=0;

		streamMessageIn=NULL;
		inputStream=NULL;

		streamMessageOut=NULL;
		outputStream=NULL;

		outputHashArray=NULL;
		outputHashLength=0;
		selfPrimarySignatureHash=NULL;
		selfSecondarySignatureHash=NULL;
		selfSigningMessage=NULL;

		inputHashArray=NULL;
		inputHashLength=0;
		brotherPrimarySignatureHash=NULL;
		brotherSecondarySignatureHash=NULL;
	}
	//Build stream data
	void gateway::buildStream()
	{
		if(streamEstTimestamp+_timeout>os::getTimestamp()) return;

		lock.acquire();
		if(!brotherPublicKey || !brotherPKFrame || !brotherStream)
		{
			lock.release();
			logError(errorPointer(new customError("Brother Undefined","Cannot build stream when the brother is undefined"),os::shared_type));
			return;
		}
		streamEstTimestamp=os::getTimestamp();
		size_t keySize=brotherPKFrame->keySize()*sizeof(uint32_t);
		os::smart_ptr<uint8_t> strmKey(new uint8_t[keySize],os::shared_type_array);
		memset(strmKey.get(),0,keySize);
		for(unsigned int i=0;i<keySize-1;++i)
			strmKey[i]=rand();
		os::smart_ptr<number> temp=brotherPKFrame->convert(strmKey.get(),keySize);
		strmKey=temp->getCompCharData(keySize);

		streamMessageOut=os::smart_ptr<message>(new message((uint16_t) (keySize+2)),os::shared_type);
		streamMessageOut->data()[0]=message::STREAM_KEY;
		streamMessageOut->data()[1]=_currentState;

		outputStream=os::smart_ptr<streamEncrypter>(new streamEncrypter(brotherStream->buildStream(strmKey.get(),keySize)),os::shared_type);

		outputHashLength=(uint16_t)(keySize+2*size::NAME_SIZE+2*size::GROUP_SIZE+8);
		outputHashArray=os::smart_ptr<uint8_t>(new uint8_t[outputHashLength],os::shared_type_array);
		memset(outputHashArray.get(),0,outputHashLength);
		memcpy(outputHashArray.get()+8,strmKey.get(),keySize);
		memcpy(outputHashArray.get()+8+keySize,selfSettings->groupID().c_str(),selfSettings->groupID().length());
		memcpy(outputHashArray.get()+8+keySize+size::GROUP_SIZE,selfSettings->nodeName().c_str(),selfSettings->nodeName().length());
		memcpy(outputHashArray.get()+8+keySize+size::NAME_SIZE+size::GROUP_SIZE,brotherSettings->groupID().c_str(),brotherSettings->groupID().length());
		memcpy(outputHashArray.get()+8+keySize+size::NAME_SIZE+2*size::GROUP_SIZE,brotherSettings->nodeName().c_str(),brotherSettings->nodeName().length());

		memcpy(streamMessageOut->data()+2,strmKey.get(),keySize);
		brotherPKFrame->encode(streamMessageOut->data()+2,keySize,brotherPublicKey);

		lock.release();
	}

	//Encrypt a message
	os::smart_ptr<message> gateway::encrypt(os::smart_ptr<message> msg)
	{
		lock.acquire();
		uint8_t msgType=msg->data()[0];
		if(!outputStream)
		{
			lock.release();
			gateway::logError(errorPointer(new customError("Undefined output stream","Cannot encrypt a message without an output stream"),os::shared_type),BASIC_ERROR_STATE);
			return NULL;
		}
		if(msgType==message::BLOCKED || msgType==message::PING ||
			msgType==message::STREAM_KEY || msgType==message::BASIC_ERROR ||
			msgType==message::TIMEOUT_ERROR || msgType==message::PERMENANT_ERROR)
		{
			lock.release();
			gateway::logError(errorPointer(new customError("Encryption error","Message type cannot be encrypted"),os::shared_type),BASIC_ERROR_STATE);
			return NULL;
		}
		size_t newSize;
		size_t encrySize;
		uint8_t* oldData=msg->data();
		if(msg->encryptionDepth()==0)
		{
			newSize=msg->size()+3;
			encrySize=msg->size()-1;

			msg->_data=new uint8_t[newSize];
			msg->_encryptionDepth=1;
			memcpy(msg->data()+4,oldData+1,encrySize);
		}
		else
		{
			newSize=msg->size()+2;
			encrySize=msg->size()-2;

			msg->_data=new uint8_t[newSize];
			msg->_encryptionDepth=msg->encryptionDepth()+1;
			memcpy(msg->data()+4,oldData+2,encrySize);
		}
		msg->data()[0]=oldData[0];
		msg->data()[1]=(uint8_t)msg->encryptionDepth();

		uint16_t encryTag;
		try
		{
			outputStream->sendData(msg->data()+4,encrySize,encryTag);
		}
		catch(errorPointer e)
		{
			lock.release();
			gateway::logError(e,BASIC_ERROR_STATE);
			delete [] oldData;
			return NULL;
		}
		catch(...)
		{
			lock.release();
			gateway::logError(errorPointer(new unknownErrorType(),os::shared_type),BASIC_ERROR_STATE);
			delete [] oldData;
			return NULL;
		}
		encryTag=os::to_comp_mode(encryTag);
		memcpy(msg->data()+2,&encryTag,2);

		msg->_size=newSize;
		msg->_messageSize=encrySize;
		delete [] oldData;
		lock.release();

		return msg;
	}
	//Decrypt a message
	os::smart_ptr<message> gateway::decrypt(os::smart_ptr<message> msg)
	{
		lock.acquire();
		uint8_t msgType=msg->data()[0];
		if(!inputStream)
		{
			lock.release();
			gateway::logError(errorPointer(new customError("Undefined input stream","Cannot decrypt a message without an input stream"),os::shared_type),BASIC_ERROR_STATE);
			return NULL;
		}
		if(msgType==message::BLOCKED || msgType==message::PING ||
			msgType==message::STREAM_KEY || msgType==message::BASIC_ERROR ||
			msgType==message::TIMEOUT_ERROR || msgType==message::PERMENANT_ERROR)
		{
			lock.release();
			gateway::logError(errorPointer(new customError("Decryption error","Message type cannot be decrypted"),os::shared_type),BASIC_ERROR_STATE);
			return NULL;
		}
		uint16_t eDepth=msg->encryptionDepth();
		if(eDepth<=0)
		{
			lock.release();
			gateway::logError(errorPointer(new customError("Decryption error","Received message is not encrypted"),os::shared_type),BASIC_ERROR_STATE);
			return NULL;
		}

		size_t newSize;
		size_t decrySize=msg->size()-4;

		uint8_t* oldData=msg->data();
		if(eDepth==1)
		{
			newSize=msg->size()-3;

			msg->_data=new uint8_t[newSize];
			memcpy(msg->data()+1,oldData+4,decrySize);
			msg->_encryptionDepth=0;
		}
		else
		{
			newSize=msg->size()-2;

			msg->_data=new uint8_t[newSize];
			memcpy(msg->data()+2,oldData+4,decrySize);
			msg->_encryptionDepth=eDepth-1;
			msg->data()[1]=(uint8_t)msg->encryptionDepth();
		}
		msg->data()[0]=oldData[0];
		uint16_t decryTag;
		uint8_t* outptr;
		memcpy(&decryTag,oldData+2,2);
		decryTag=os::from_comp_mode(decryTag);
		try
		{
			if(eDepth==1)
				outptr=inputStream->recieveData(msg->data()+1,decrySize,decryTag);
			else
				outptr=inputStream->recieveData(msg->data()+2,decrySize,decryTag);

			if(!outptr)
				throw errorPointer(new customError("Decryption Failure","Gateway failed to decrypt a packet"),os::shared_type);
		}
		catch(errorPointer e)
		{
			lock.release();
			gateway::logError(e,BASIC_ERROR_STATE);
			delete [] oldData;
			return NULL;
		}
		catch(...)
		{
			lock.release();
			gateway::logError(errorPointer(new unknownErrorType(),os::shared_type),BASIC_ERROR_STATE);
			delete [] oldData;
			return NULL;
		}
		msg->_messageSize=decrySize;
		msg->_size=newSize;
		delete [] oldData;
		lock.release();

		return msg;
	}
	//Resets error flags
	void gateway::purgeLastError()
	{
		lock.acquire();
		if(brotherSettings) _currentState=SETTINGS_EXCHANGED;
		else _currentState=UNKNOWN_BROTHER;

		_lastError=NULL;
		_lastErrorLevel=UNKNOWN_STATE;

		lock.release();
	}


}

#endif

///@endcond
