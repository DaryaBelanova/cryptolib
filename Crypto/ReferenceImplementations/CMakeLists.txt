# CMakeList.txt : CMake project for ReferenceImplementations, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
project(ReferenceImplementations)

set(CMAKE_CXX_STANDARD 17)

add_library( ReferenceImplementations STATIC)

file(GLOB_RECURSE CIPHERMODES_SOURCES ciphermodes/*.cpp)
file(GLOB_RECURSE CIPHERSUITE_SOURCES ciphersuite/*.cpp)
file(GLOB_RECURSE CRISP_SOURCES crisp/*.cpp)
file(GLOB_RECURSE HASHFUNC_SOURCES hashfunc/*.cpp)
file(GLOB_RECURSE HMAC_SOURCES hmac/*.cpp)
file(GLOB_RECURSE KDF_SOURCES kdf/*.cpp)
file(GLOB_RECURSE KEXP15KIMP15_SOURCES kexp15kimp15/*.cpp)
file(GLOB_RECURSE PROTOQA_SOURCES protoqa/*.cpp)

target_sources(ReferenceImplementations PRIVATE ${CIPHERMODES_SOURCES} ${CIPHERSUITE_SOURCES} ${CRISP_SOURCES} ${HASHFUNC_SOURCES} ${HMAC_SOURCES}  ${KDF_SOURCES} ${KEXP15KIMP15_SOURCES} ${PROTOQA_SOURCES}  "crisp/CrispMessage.h")

target_include_directories(ReferenceImplementations PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/ciphermodes
        ${CMAKE_CURRENT_SOURCE_DIR}/ciphersuite
        ${CMAKE_CURRENT_SOURCE_DIR}/crisp
        ${CMAKE_CURRENT_SOURCE_DIR}/hashfunc
        ${CMAKE_CURRENT_SOURCE_DIR}/hmac
        ${CMAKE_CURRENT_SOURCE_DIR}/kdf
        ${CMAKE_CURRENT_SOURCE_DIR}/kexp15kimp15
        ${CMAKE_CURRENT_SOURCE_DIR}/protoqa)