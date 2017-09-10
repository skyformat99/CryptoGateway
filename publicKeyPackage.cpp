/**
 * Implements a bank of public key types to
 * be accessed at run-time.  Essentially acts
 * as a meta-object access bank.
 **/

 ///@cond INTERNAL

#ifndef PUBLIC_KEY_PACKAGE_CPP
#define PUBLIC_KEY_PACKAGE_CPP

#include <string>
#include <stdint.h>
#include "publicKeyPackage.h"

namespace crypto {

/*------------------------------------------------------------
     Public Key Package
 ------------------------------------------------------------*/

    static os::smart_ptr<publicKeyTypeBank> _singleton;
    //Public key package constructor
    publicKeyTypeBank::publicKeyTypeBank()
    {
        setDefaultPackage(os::smart_ptr<publicKeyPackageFrame>(new publicKeyPackage<publicRSA>(),os::shared_type));
    }
    //Singleton constructor
    os::smart_ptr<publicKeyTypeBank> publicKeyTypeBank::singleton()
    {
        if(!_singleton) _singleton=os::smart_ptr<publicKeyTypeBank>(new publicKeyTypeBank(),os::shared_type);
        return _singleton;
    }

    //Sets the default package value
    void publicKeyTypeBank::setDefaultPackage(os::smart_ptr<publicKeyPackageFrame> package)
    {
        if(!package) return;
        pushPackage(package);
        _defaultPackage=findPublicKey(package->algorithm());
    }
    //Add a package to the package list
    void publicKeyTypeBank::pushPackage(os::smart_ptr<publicKeyPackageFrame> package)
    {
        if(!package) return;

        //Find by algorithm ID
        if(package->algorithm()+1>packageVector.size())
        packageVector.resize(package->algorithm()+1);

        packageVector[package->algorithm()]=package;
    }
    //Given stream descriptions, find package
    const os::smart_ptr<publicKeyPackageFrame> publicKeyTypeBank::findPublicKey(uint16_t pkID) const
    {
        if(pkID>packageVector.size()) return NULL;
        return packageVector[pkID];
    }
    //Given a stream name and a hash name, find the package
    const os::smart_ptr<publicKeyPackageFrame> publicKeyTypeBank::findPublicKey(const std::string& pkName) const
    {
        for(unsigned int i=0;i<packageVector.size();++i)
        {
            if(packageVector[i] && pkName==packageVector[i]->algorithmName())
                return packageVector[i];
        }
        return NULL;
    }
}

#endif
///@endcond