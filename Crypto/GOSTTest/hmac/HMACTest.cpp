#include <cassert>
#include "HMACTest.h"
#include <iostream>

HMACTest::HMACTest() : hmac256_(key_), hmac512_(key_) {
}

void HMACTest::assert_finalize_256() {
	std::cout << "Testing HMAC-256 finalization..." << std::endl;
	hmac256_.update(data_);

	std::vector<uint8_t> calculated_hmac;
	hmac256_.finalize(calculated_hmac);

	assert(calculated_hmac == valid_hmac256_);
	std::cout << "HMAC-256 finalization test passed successfully!" << std::endl;

	hmac256_.refresh();
}

void HMACTest::assert_finalize_512() {
	std::cout << "Testing HMAC-512 finalization..." << std::endl;
	hmac512_.update(data_);

	std::vector<uint8_t> calculated_hmac;
	hmac512_.finalize(calculated_hmac);

	assert(calculated_hmac == valid_hmac512_);
	std::cout << "HMAC-512 finalization test passed successfully!" << std::endl;

	hmac512_.refresh();
}

void HMACTest::assert_all_functions() {
	std::cout << "\nRunning all HMAC tests..." << std::endl;
	assert_finalize_256();
	assert_finalize_512();
	std::cout << "All HMAC tests completed successfully!" << std::endl;
}