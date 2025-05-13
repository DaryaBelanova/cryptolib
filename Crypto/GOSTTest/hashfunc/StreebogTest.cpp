#include <cassert>
#include "StreebogTest.h"
#include <iostream>


StreebogTest::StreebogTest() : streebog512_(), streebog256_() {
}

void StreebogTest::assert_M1_hash_512() {
	std::cout << "Testing Streebog-512 hash for M1..." << std::endl;
	streebog512_.refresh();
	streebog512_.update(M1);

	std::vector<uint8_t> hash = {};
	streebog512_.finalize(hash);

	assert(hash == M1hash512);
	std::cout << "Streebog-512 hash for M1 test passed successfully!" << std::endl;
}

void StreebogTest::assert_M1_hash_256() {
	std::cout << "Testing Streebog-256 hash for M1..." << std::endl;
	streebog256_.refresh();
	streebog256_.update(M1);

	std::vector<uint8_t> hash = {};
	streebog256_.finalize(hash);

	assert(hash == M1hash256);
	std::cout << "Streebog-256 hash for M1 test passed successfully!" << std::endl;
}

void StreebogTest::assert_M2_hash_512() {
	std::cout << "Testing Streebog-512 hash for M2..." << std::endl;
	streebog512_.refresh();
	streebog512_.update(M2);

	std::vector<uint8_t> hash = {};
	streebog512_.finalize(hash);

	assert(hash == M2hash512);
	std::cout << "Streebog-512 hash for M2 test passed successfully!" << std::endl;
}

void StreebogTest::assert_M2_hash_256() {
	std::cout << "Testing Streebog-256 hash for M2..." << std::endl;
	streebog256_.refresh();
	streebog256_.update(M2);

	std::vector<uint8_t> hash = {};
	streebog256_.finalize(hash);

	assert(hash == M2hash256);
	std::cout << "Streebog-256 hash for M2 test passed successfully!" << std::endl;
}

void StreebogTest::assert_all_functions() {
	std::cout << "\nRunning all Streebog hash tests..." << std::endl;
	assert_M1_hash_512();
	assert_M1_hash_256();

	assert_M2_hash_512();
	assert_M2_hash_256();
	std::cout << "All Streebog hash tests completed successfully!" << std::endl;
}