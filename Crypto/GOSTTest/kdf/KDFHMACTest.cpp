#include <cassert>
#include "KDFHMACTest.h"
#include <iostream>

KDFHMACTest::KDFHMACTest() : kdf_hmac256_(key_, R_, L_) {
}

void KDFHMACTest::assert_get_k1() {
	std::cout << "Testing KDF HMAC256 K1 generation..." << std::endl;
	std::vector<uint8_t> k1;

	kdf_hmac256_.get_ki(1, label_, seed_, k1);

	assert(k1 == valid_k1_);
	std::cout << "KDF HMAC256 K1 generation test passed successfully!" << std::endl;
}

void KDFHMACTest::assert_get_k2() {
	std::cout << "Testing KDF HMAC256 K2 generation..." << std::endl;
	std::vector<uint8_t> k2;

	kdf_hmac256_.get_ki(2, label_, seed_, k2);

	assert(k2 == valid_k2_);
	std::cout << "KDF HMAC256 K2 generation test passed successfully!" << std::endl;
}

void KDFHMACTest::assert_get_k_seq() {
	std::cout << "Testing KDF HMAC256 sequential key generation..." << std::endl;
	std::vector<uint8_t> k_seq;

	kdf_hmac256_.get_k_seq(2, label_, seed_, k_seq);

	assert(k_seq == valid_k1_k2_);
	std::cout << "KDF HMAC256 sequential key generation test passed successfully!" << std::endl;
}

void KDFHMACTest::assert_all_functions() {
	std::cout << "\nRunning all KDF HMAC256 tests..." << std::endl;
	assert_get_k1();
	assert_get_k2();
	assert_get_k_seq();
	std::cout << "All KDF HMAC256 tests completed successfully!" << std::endl;
}

