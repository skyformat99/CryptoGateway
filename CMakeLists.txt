IF(NOT CRYPTOGATEWAY_CMAKE)
SET(CRYPTOGATEWAY_CMAKE 1)

INCLUDE(${GLOBAL_DIR}/Datastructures/CMakeLists.txt)
INCLUDE(${GLOBAL_DIR}/UnitTest/CMakeLists.txt)
INCLUDE(${GLOBAL_DIR}/osMechanics/CMakeLists.txt)

MESSAGE(STATUS )
MESSAGE(STATUS ========= CryptoGateway ==========)
MESSAGE(STATUS )

SET(CUR_SRC ${GLOBAL_DIR}/CryptoGateway)
INCLUDE_DIRECTORIES(${GLOBAL_DIR})

SET( SRC_H
	${CUR_SRC}/CryptoGateway.h
	${CUR_SRC}/cryptoLogging.h
	${CUR_SRC}/streamCipher.h
	${CUR_SRC}/RC4_Hash.h

	${CUR_SRC}/cryptoNumber.h
	${CUR_SRC}/cryptoHash.h
	${CUR_SRC}/cryptoPublicKey.h

	${CUR_SRC}/binaryEncryption.h
	${CUR_SRC}/XMLEncryption.h

	${CUR_SRC}/cryptoError.h
	${CUR_SRC}/streamPackage.h
	${CUR_SRC}/publicKeyPackage.h

	${CUR_SRC}/cryptoConstants.h
	${CUR_SRC}/cryptoCHeaders.h
	${CUR_SRC}/hexConversion.h

	${CUR_SRC}/gateway.h
	${CUR_SRC}/message.h
	${CUR_SRC}/keyBank.h
	${CUR_SRC}/user.h
)

SET( SRC_CPP
	${CUR_SRC}/cryptoLogging.cpp
	${CUR_SRC}/streamCipher.cpp
	${CUR_SRC}/RC4_Hash.cpp

	${CUR_SRC}/cryptoNumber.cpp
	${CUR_SRC}/cryptoHash.cpp
	${CUR_SRC}/cryptoPublicKey.cpp

	${CUR_SRC}/binaryEncryption.cpp
	${CUR_SRC}/XMLEncryption.cpp

	${CUR_SRC}/cryptoError.cpp
	${CUR_SRC}/streamPackage.cpp
	${CUR_SRC}/publicKeyPackage.cpp

	${CUR_SRC}/cryptoConstants.cpp
	${CUR_SRC}/cryptoCSource.cpp
	${CUR_SRC}/hexConversion.cpp

	${CUR_SRC}/gateway.cpp
	${CUR_SRC}/message.cpp
	${CUR_SRC}/keyBank.cpp
	${CUR_SRC}/user.cpp
)

ADD_LIBRARY( CryptoGateway STATIC
	${SRC_CPP}
	${SRC_H}
)
TARGET_LINK_LIBRARIES( CryptoGateway
	${OS_LIBS}
	${EXE_LIBS}
)
SET(EXE_LIBS ${EXE_LIBS} CryptoGateway)
INCLUDE(${GLOBAL_DIR}/CryptoGateway/test/CMakeLists.txt)

ENDIF(NOT CRYPTOGATEWAY_CMAKE)
