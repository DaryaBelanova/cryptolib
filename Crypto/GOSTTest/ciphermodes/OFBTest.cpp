#include <cassert>
#include "OFBTest.h"
#include <iostream>


OFBTest::OFBTest() : alg128_(key128_), alg64_(key64_), ofb128_(alg128_, iv128_), ofb64_(alg64_, iv64_) {
}

void OFBTest::assert_encrypt128() {
	std::cout << "Testing OFB 128-bit encryption..." << std::endl;
	ofb128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	ofb128_.encrypt(plain_flow128_, result);

	assert(result == cipher_flow128_);
	std::cout << "OFB 128-bit encryption test passed successfully!" << std::endl;
}

void OFBTest::assert_encrypt_step_by_step128() {
	std::cout << "Testing OFB 128-bit step-by-step encryption..." << std::endl;
	ofb128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	for (size_t i = 0; i < 4; i++) {
		// compare control input gamma with first n elements in register in ofb (real input gamma)
		assert(std::equal(input_gamma_blocks128_[i].begin(), input_gamma_blocks128_[i].end(), ofb128_.curr_register_.begin()));

		ofb128_.encrypt(plain_blocks128_[i], result);

		assert(ofb128_.curr_gamma_ == output_gamma_blocks128_[i]);

		assert(result == cipher_blocks128_[i]);
	}
	std::cout << "OFB 128-bit step-by-step encryption test passed successfully!" << std::endl;
}

void OFBTest::assert_decrypt128() {
	std::cout << "Testing OFB 128-bit decryption..." << std::endl;
	ofb128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	ofb128_.decrypt(cipher_flow128_, result);

	assert(result == plain_flow128_);
	std::cout << "OFB 128-bit decryption test passed successfully!" << std::endl;
}

void OFBTest::assert_encrypt64() {
	std::cout << "Testing OFB 64-bit encryption..." << std::endl;
	ofb64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	ofb64_.encrypt(plain_flow64_, result);

	assert(result == cipher_flow64_);
	std::cout << "OFB 64-bit encryption test passed successfully!" << std::endl;
}

void OFBTest::assert_encrypt_step_by_step64() {
	std::cout << "Testing OFB 64-bit step-by-step encryption..." << std::endl;
	ofb64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	for (size_t i = 0; i < 4; i++) {
		assert(std::equal(input_gamma_blocks64_[i].begin(), input_gamma_blocks64_[i].end(), ofb64_.curr_register_.begin()));

		ofb64_.encrypt(plain_blocks64_[i], result);

		assert(ofb64_.curr_gamma_ == output_gamma_blocks64_[i]);

		assert(result == cipher_blocks64_[i]);
	}
	std::cout << "OFB 64-bit step-by-step encryption test passed successfully!" << std::endl;
}

void OFBTest::assert_decrypt64() {
	std::cout << "Testing OFB 64-bit decryption..." << std::endl;
	ofb64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	ofb64_.decrypt(cipher_flow64_, result);

	assert(result == plain_flow64_);
	std::cout << "OFB 64-bit decryption test passed successfully!" << std::endl;
}

void OFBTest::assert_all_functions() {
	std::cout << "\nRunning all OFB mode tests..." << std::endl;
	assert_encrypt128();
	assert_encrypt_step_by_step128();
	assert_decrypt128();

	assert_encrypt64();
	assert_encrypt_step_by_step64();
	assert_decrypt64();
	std::cout << "All OFB mode tests completed successfully!" << std::endl;
}