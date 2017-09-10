IF(NOT CRYPTOGATEWAY_TEST_CMAKE)
SET(CRYPTOGATEWAY_TEST_CMAKE 1)

MESSAGE(STATUS )
MESSAGE(STATUS --------- Tests --------- )
MESSAGE(STATUS )

SET(CUR_SRC ${GLOBAL_DIR}/CryptoGateway/test)

SET( SRC_H
	${CUR_SRC}/cryptoTest.h
	${CUR_SRC}/c_cryptoTesting.h
	${CUR_SRC}/hashTest.h
	${CUR_SRC}/streamTest.h
	${CUR_SRC}/publicKeyTest.h
	${CUR_SRC}/cryptoFileTest.h

	${CUR_SRC}/staticTestKeys.h
	${CUR_SRC}/testKeyGeneration.h
	${CUR_SRC}/gatewayTest.h
)

SET( SRC_CPP
	${CUR_SRC}/cryptoTest.cpp
	${CUR_SRC}/c_cryptoTesting.cpp
	${CUR_SRC}/cryptoNumberTest.cpp
	${CUR_SRC}/hashTest.cpp
	${CUR_SRC}/streamTest.cpp
	${CUR_SRC}/cryptoFileTest.cpp

	${CUR_SRC}/staticTestKeys.cpp
	${CUR_SRC}/testKeyGeneration.cpp
	${CUR_SRC}/gatewayTest.cpp
)

ADD_LIBRARY( CryptoGatewayTest STATIC
	${SRC_CPP}
	${SRC_H}
)
TARGET_LINK_LIBRARIES( CryptoGatewayTest
	${OS_LIBS}
	${EXE_LIBS}
)
SET(TEST_LIBS ${TEST_LIBS} CryptoGatewayTest)

ENDIF(NOT CRYPTOGATEWAY_TEST_CMAKE)
