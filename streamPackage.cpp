/**
 * Implements a a bank of stream ciphers and hash algorithms to
 * be accessed at run-time.  Essentially acts
 * as a meta-object access bank.
 **/

 ///@cond INTERNAL

#ifndef STREAM_PACKAGE_CPP
#define STREAM_PACKAGE_CPP

#include <string>
#include <stdint.h>
#include "streamPackage.h"

namespace crypto {

/*------------------------------------------------------------
     Stream Package
 ------------------------------------------------------------*/

    static os::smart_ptr<streamPackageTypeBank> _singleton;
    //Stream package constructor
    streamPackageTypeBank::streamPackageTypeBank()
    {
        //RC-Four stream, RC4 hash
        setDefaultPackage(os::smart_ptr<streamPackageFrame>(new streamPackage<RCFour,rc4Hash>(),os::shared_type));
		pushPackage(os::smart_ptr<streamPackageFrame>(new streamPackage<RCFour,xorHash>(),os::shared_type));
    }
    //Singleton constructor
    os::smart_ptr<streamPackageTypeBank> streamPackageTypeBank::singleton()
    {
        if(!_singleton) _singleton=os::smart_ptr<streamPackageTypeBank>(new streamPackageTypeBank(),os::shared_type);
        return _singleton;
    }

    //Sets the default package value
    void streamPackageTypeBank::setDefaultPackage(os::smart_ptr<streamPackageFrame> package)
    {
		if(!package) return;
        pushPackage(package);
		_defaultPackage=findStream(package->streamAlgorithm(),package->hashAlgorithm());
    }
    //Add a package to the package list
    void streamPackageTypeBank::pushPackage(os::smart_ptr<streamPackageFrame> package)
    {
        if(!package) return;

        //Find by stream first
		if(package->streamAlgorithm()+1>packageVector.size())
			packageVector.resize(package->streamAlgorithm()+1);

		if(!packageVector[package->streamAlgorithm()])
			packageVector[package->streamAlgorithm()]=os::smart_ptr<std::vector<os::smart_ptr<streamPackageFrame> > >(new std::vector<os::smart_ptr<streamPackageFrame> >(),os::shared_type);
		os::smart_ptr<std::vector<os::smart_ptr<streamPackageFrame> > > temp=packageVector[package->streamAlgorithm()];

		//Find by hash
		if(package->hashAlgorithm()+1>temp->size())
			temp->resize(package->hashAlgorithm()+1);
		if(!(*temp)[package->hashAlgorithm()])
			(*temp)[package->hashAlgorithm()]=package;
	}
    //Given stream descriptions, find package
    const os::smart_ptr<streamPackageFrame> streamPackageTypeBank::findStream(uint16_t streamID,uint16_t hashID) const
    {
        if(streamID>packageVector.size()) return NULL;
        if(!packageVector[streamID]) return NULL;

        if(hashID>packageVector[streamID]->size()) return NULL;
        return (*packageVector[streamID])[hashID].get();
    }
	//Given a stream name and a hash name, find the package
	const os::smart_ptr<streamPackageFrame> streamPackageTypeBank::findStream(const std::string& streamName,const std::string& hashName) const
	{
		unsigned int streamID=0;
		unsigned int hashID=0;
		while(streamID<packageVector.size())
		{
			hashID=0;
			while(packageVector[streamID] && hashID<packageVector[streamID]->size())
			{
				os::smart_ptr<streamPackageFrame> pck =(*packageVector[streamID])[hashID];
				if(pck && pck->streamAlgorithmName()==streamName && pck->hashAlgorithmName()==hashName)
					return pck.get();
				hashID++;
			}
			streamID++;
		}
		return NULL;
	}
}

#endif
///@endcond