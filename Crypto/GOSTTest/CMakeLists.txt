cmake_minimum_required(VERSION 3.8)
project(GOSTTest)

set(CMAKE_CXX_STANDARD 17)

add_executable(GOSTTest
        main.cpp
        ciphersuite/KuznyechikTest.h ciphersuite/KuznyechikTest.cpp
        ciphersuite/MagmaTest.h ciphersuite/MagmaTest.cpp

        ciphermodes/CBCTest.h ciphermodes/CBCTest.cpp
        ciphermodes/CFBTest.h ciphermodes/CFBTest.cpp
        ciphermodes/CMACTest.h ciphermodes/CMACTest.cpp
        ciphermodes/CTRTest.h ciphermodes/CTRTest.cpp
        ciphermodes/ECBTest.h ciphermodes/ECBTest.cpp
        ciphermodes/OFBTest.h ciphermodes/OFBTest.cpp

        crisp/CrispTest.h crisp/CrispTest.cpp

        hashfunc/StreebogTest.h hashfunc/StreebogTest.cpp

        hmac/HMACTest.h hmac/HMACTest.cpp

        kdf/KDFCMACTest.h kdf/KDFCMACTest.cpp
        kdf/KDFHMACTest.h kdf/KDFHMACTest.cpp

        kexp15kimp15/KExp15Test.h kexp15kimp15/KExp15Test.cpp
)

target_link_libraries(GOSTTest PRIVATE ReferenceImplementations)

target_include_directories(GOSTTest PRIVATE ${CMAKE_SOURCE_DIR}/ReferenceImplementations)

set_target_properties(GOSTTest PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)