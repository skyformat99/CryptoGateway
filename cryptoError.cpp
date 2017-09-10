/**
 * Implements the error sender and listeners.
 * These classes allow for managing the throwing
 * of crypto::errorPointer.  Consult cryptoError.h
 * for details.
 **/

 ///@cond INTERNAL

#ifndef CRYPTO_ERROR_CPP
#define CRYPTO_ERROR_CPP

#include "cryptoError.h"

namespace crypto {

/*------------------------------------------------------------
     Error Listener
 ------------------------------------------------------------*/

	//Deletes an error listener
	errorListener::~errorListener() throw()
	{
		for(auto trc=senders.first();trc;++trc)
		{
			trc->listenerLock.acquire();
			mtx.acquire();
			trc->errorListen.remove(this);
			mtx.release();
			trc->listenerLock.release();
		}
	}

/*------------------------------------------------------------
     Error Sender
 ------------------------------------------------------------*/

	//Error destructor
	errorSender::~errorSender() throw()
	{
		listenerLock.acquire();
		for(auto trc=errorListen.first();trc;++trc)
		{
			trc->mtx.acquire();
			trc->senders.remove(this);
			trc->mtx.release();
		}
		listenerLock.release();
	}
	//Pushes error listeners onto the sender
	void errorSender::pushErrorListener(os::smart_ptr<errorListener> listener)
	{
		if(!listener) return;
		listenerLock.acquire();
		listener->mtx.acquire();

		errorListen.insert(listener);
		listener->senders.insert(this);

		listener->mtx.release();
		listenerLock.release();
	}
	//Remove error listener from the sender
	void errorSender::removeErrrorListener(os::smart_ptr<errorListener> listener)
	{
		if(!listener) return;
		listenerLock.acquire();
		listener->mtx.acquire();

		errorListen.remove(listener);
		listener->senders.remove(this);

		listener->mtx.release();
		listenerLock.release();
	}
	//Logs the error
	void errorSender::logError(errorPointer elm)
	{
		listenerLock.acquire();
		errorLog.insert(elm);
		if(errorLog.size()>_logLength) errorLog.remove(&errorLog.first());

		for(auto trc=errorListen.first();trc;++trc)
		{
			trc->mtx.acquire();
			trc->receiveError(elm,this);
			trc->mtx.release();
		}
		listenerLock.release();
	}
	//Pop an error
	errorPointer errorSender::popError()
	{
		listenerLock.acquire();
		auto tem=errorLog.last();
		if(!tem)
		{
			listenerLock.release();
			return NULL;
		}
		errorPointer ptr=&tem;
		errorLog.remove(ptr);
		listenerLock.release();
		return ptr;
	}
	//Set the log length
	void errorSender::setLogLength(unsigned int logLength)
	{
		if(logLength<1) return;

		listenerLock.acquire();
		_logLength=logLength;

		while(errorLog.size()>logLength)
			errorLog.remove(&errorLog.last());

		listenerLock.release();
	}
}

#endif

///@endcond