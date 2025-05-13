#include <cassert>
#include "CTRTest.h"
#include <iostream>


CTRTest::CTRTest() : alg128_(key128_), alg64_(key64_), ctr128_(alg128_, iv128_), ctr64_(alg64_, iv64_) {
}

void CTRTest::assert_encrypt128() {
	std::cout << "Testing CTR 128-bit encryption..." << std::endl;
	ctr128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	ctr128_.encrypt(plain_flow128_, result);

	assert(result == cipher_flow128_);
	std::cout << "CTR 128-bit encryption test passed successfully!" << std::endl;
}

void CTRTest::assert_encrypt_step_by_step128() {
	std::cout << "Testing CTR 128-bit step-by-step encryption..." << std::endl;
	ctr128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	for (size_t i = 0; i < 4; i++) {
		assert(ctr128_.curr_ctr_ == input_gamma_blocks128_[i]);

		ctr128_.encrypt(plain_blocks128_[i], result);

		assert(ctr128_.curr_gamma_ == output_gamma_blocks128_[i]);

		assert(result == cipher_blocks128_[i]);
	}
	std::cout << "CTR 128-bit step-by-step encryption test passed successfully!" << std::endl;
}

void CTRTest::assert_decrypt128() {
	std::cout << "Testing CTR 128-bit decryption..." << std::endl;
	ctr128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	ctr128_.decrypt(cipher_flow128_, result);

	assert(result == plain_flow128_);
	std::cout << "CTR 128-bit decryption test passed successfully!" << std::endl;
}

void CTRTest::assert_encrypt64() {
	std::cout << "Testing CTR 64-bit encryption..." << std::endl;
	ctr64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	ctr64_.encrypt(plain_flow64_, result);

	assert(result == cipher_flow64_);
	std::cout << "CTR 64-bit encryption test passed successfully!" << std::endl;
}

void CTRTest::assert_encrypt_step_by_step64() {
	std::cout << "Testing CTR 64-bit step-by-step encryption..." << std::endl;
	ctr64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	for (size_t i = 0; i < 4; i++) {
		assert(ctr64_.curr_ctr_ == input_gamma_blocks64_[i]);

		ctr64_.encrypt(plain_blocks64_[i], result);

		assert(ctr64_.curr_gamma_ == output_gamma_blocks64_[i]);

		assert(result == cipher_blocks64_[i]);
	}
	std::cout << "CTR 64-bit step-by-step encryption test passed successfully!" << std::endl;
}

void CTRTest::assert_decrypt64() {
	std::cout << "Testing CTR 64-bit decryption..." << std::endl;
	ctr64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	ctr64_.decrypt(cipher_flow64_, result);

	assert(result == plain_flow64_);
	std::cout << "CTR 64-bit decryption test passed successfully!" << std::endl;
}

void CTRTest::assert_all_functions() {
	std::cout << "\nRunning all CTR mode tests..." << std::endl;
	assert_encrypt128();
	assert_encrypt_step_by_step128();
	assert_decrypt128();

	assert_encrypt64();
	assert_encrypt_step_by_step64();
	assert_decrypt64();
	std::cout << "All CTR mode tests completed successfully!" << std::endl;
}