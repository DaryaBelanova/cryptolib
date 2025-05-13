# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

project ("Crypto")


add_subdirectory(ReferenceImplementations)
add_subdirectory(GOSTTest)
add_subdirectory(CrispApp)
add_subdirectory(DirectCrypto)