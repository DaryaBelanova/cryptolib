#include <cassert>
#include "CBCTest.h"
#include <iostream>
#include <iomanip>


CBCTest::CBCTest() : alg128_(key128_), alg64_(key64_), cbc128_(alg128_, iv128_), cbc64_(alg64_, iv64_) {
}

void CBCTest::assert_encrypt128() {
	std::cout << "Testing CBC 128-bit encryption..." << std::endl;
	cbc128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	cbc128_.encrypt(plain_flow128_, result);

	assert(result == cipher_flow128_);
	std::cout << "CBC 128-bit encryption test passed successfully!" << std::endl;
}

void CBCTest::assert_encrypt_step_by_step128() {
	std::cout << "Testing CBC 128-bit step-by-step encryption..." << std::endl;
	cbc128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	std::array<uint8_t, Kuznyechik::byte_block_size> real_cipher_input = {};
	for (size_t i = 0; i < 4; i++) {
		std::copy(cbc128_.curr_register_.begin(), cbc128_.curr_register_.begin() + Kuznyechik::byte_block_size, real_cipher_input.begin());
		for (size_t j = 0; j < Kuznyechik::byte_block_size; j++) {
			real_cipher_input[j] ^= plain_blocks128_[i][j];
		}
		// compare control cipher input with xor of first n elements in register in cbc (real input gamma) and plaintext
		assert(std::equal(input_blocks128_[i].begin(), input_blocks128_[i].end(), real_cipher_input.begin()));

		cbc128_.encrypt(plain_blocks128_[i], result);

		// compare control output gamma with last n elements in register in cbc (real output gamma)
		assert(std::equal(cbc128_.curr_register_.end() - Kuznyechik::byte_block_size, cbc128_.curr_register_.end(), cipher_blocks128_[i].begin()));

		assert(result == cipher_blocks128_[i]);
	}
	std::cout << "CBC 128-bit step-by-step encryption test passed successfully!" << std::endl;
}

void CBCTest::assert_decrypt128() {
	std::cout << "Testing CBC 128-bit decryption..." << std::endl;
	cbc128_.refresh_iv(iv128_);

	std::vector<uint8_t> result;
	cbc128_.decrypt(cipher_flow128_, result);

	assert(result == plain_flow128_);
	std::cout << "CBC 128-bit decryption test passed successfully!" << std::endl;
}

void CBCTest::assert_encrypt64() {
	std::cout << "Testing CBC 64-bit encryption..." << std::endl;
	cbc64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	cbc64_.encrypt(plain_flow64_, result);

	assert(result == cipher_flow64_);
	std::cout << "CBC 64-bit encryption test passed successfully!" << std::endl;
}

void CBCTest::assert_encrypt_step_by_step64() {
	std::cout << "Testing CBC 64-bit step-by-step encryption..." << std::endl;
	cbc64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	std::array<uint8_t, Magma::byte_block_size> real_cipher_input = {};
	for (size_t i = 0; i < 4; i++) {
		std::copy(cbc64_.curr_register_.begin(), cbc64_.curr_register_.begin() + Magma::byte_block_size, real_cipher_input.begin());
		for (size_t j = 0; j < Magma::byte_block_size; j++) {
			real_cipher_input[j] ^= plain_blocks64_[i][j];
		}
		// compare control cipher input with xor of first n elements in register in cbc (real input gamma) and plaintext
		assert(std::equal(input_blocks64_[i].begin(), input_blocks64_[i].end(), real_cipher_input.begin()));

		cbc64_.encrypt(plain_blocks64_[i], result);

		assert(std::equal(cbc64_.curr_register_.end() - Magma::byte_block_size, cbc64_.curr_register_.end(), cipher_blocks64_[i].begin()));

		assert(result == cipher_blocks64_[i]);
	}
	std::cout << "CBC 64-bit step-by-step encryption test passed successfully!" << std::endl;
}

void CBCTest::assert_decrypt64() {
	std::cout << "Testing CBC 64-bit decryption..." << std::endl;
	cbc64_.refresh_iv(iv64_);

	std::vector<uint8_t> result;
	cbc64_.decrypt(cipher_flow64_, result);

	assert(result == plain_flow64_);
	std::cout << "CBC 64-bit decryption test passed successfully!" << std::endl;
}

void CBCTest::assert_all_functions() {
	std::cout << "\nRunning all CBC mode tests..." << std::endl;
	assert_encrypt128();
	assert_encrypt_step_by_step128();
	assert_decrypt128();

	assert_encrypt64();
	assert_encrypt_step_by_step64();
	assert_decrypt64();
	std::cout << "All CBC mode tests completed successfully!" << std::endl;
}