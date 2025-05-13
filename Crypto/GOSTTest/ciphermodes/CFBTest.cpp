#include <cassert>
#include "CFBTest.h"
#include <iostream>


CFBTest::CFBTest() : alg128_(key128_), alg64_(key64_), cfb128_(alg128_, iv128_), cfb64_(alg64_, iv64_) {
}

void CFBTest::assert_encrypt128() {
	std::cout << "Testing CFB 128-bit encryption..." << std::endl;
	cfb128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	cfb128_.encrypt(plain_flow128_, result);

	assert(result == cipher_flow128_);
	std::cout << "CFB 128-bit encryption test passed successfully!" << std::endl;
}

void CFBTest::assert_encrypt_step_by_step128() {
	std::cout << "Testing CFB 128-bit step-by-step encryption..." << std::endl;
	cfb128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	for (size_t i = 0; i < 4; i++) {
		// compare control input gamma with first n elements in register in cfb (real input gamma)
		assert(std::equal(input_gamma_blocks128_[i].begin(), input_gamma_blocks128_[i].end(), cfb128_.curr_register_.begin()));

		cfb128_.encrypt(plain_blocks128_[i], result);

		assert(cfb128_.curr_gamma_ == output_gamma_blocks128_[i]);

		assert(result == cipher_blocks128_[i]);
	}
	std::cout << "CFB 128-bit step-by-step encryption test passed successfully!" << std::endl;
}

void CFBTest::assert_decrypt128() {
	std::cout << "Testing CFB 128-bit decryption..." << std::endl;
	cfb128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	cfb128_.decrypt(cipher_flow128_, result);

	assert(result == plain_flow128_);
	std::cout << "CFB 128-bit decryption test passed successfully!" << std::endl;
}

void CFBTest::assert_encrypt64() {
	std::cout << "Testing CFB 64-bit encryption..." << std::endl;
	cfb64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	cfb64_.encrypt(plain_flow64_, result);

	assert(result == cipher_flow64_);
	std::cout << "CFB 64-bit encryption test passed successfully!" << std::endl;
}

void CFBTest::assert_encrypt_step_by_step64() {
	std::cout << "Testing CFB 64-bit step-by-step encryption..." << std::endl;
	cfb64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	for (size_t i = 0; i < 4; i++) {
		assert(std::equal(input_gamma_blocks64_[i].begin(), input_gamma_blocks64_[i].end(), cfb64_.curr_register_.begin()));

		cfb64_.encrypt(plain_blocks64_[i], result);

		assert(cfb64_.curr_gamma_ == output_gamma_blocks64_[i]);

		assert(result == cipher_blocks64_[i]);
	}
	std::cout << "CFB 64-bit step-by-step encryption test passed successfully!" << std::endl;
}

void CFBTest::assert_decrypt64() {
	std::cout << "Testing CFB 64-bit decryption..." << std::endl;
	cfb64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	cfb64_.decrypt(cipher_flow64_, result);

	assert(result == plain_flow64_);
	std::cout << "CFB 64-bit decryption test passed successfully!" << std::endl;
}

void CFBTest::assert_all_functions() {
	std::cout << "\nRunning all CFB mode tests..." << std::endl;
	assert_encrypt128();
	assert_encrypt_step_by_step128();
	assert_decrypt128();

	assert_encrypt64();
	assert_encrypt_step_by_step64();
	assert_decrypt64();
	std::cout << "All CFB mode tests completed successfully!" << std::endl;
}