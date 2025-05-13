#include <cassert>
#include "ECBTest.h"
#include <iostream>


ECBTest::ECBTest() : alg128_(key128_), alg64_(key64_), ecb128_(alg128_), ecb64_(alg64_) {
}



void ECBTest::assert_encrypt128() {
	std::cout << "Testing ECB 128-bit encryption..." << std::endl;
	std::vector<uint8_t> result;
	ecb128_.encrypt(plain_flow128_, result);

	assert(result == cipher_flow128_);
	std::cout << "ECB 128-bit encryption test passed successfully!" << std::endl;
}

void ECBTest::assert_decrypt128() {
	std::cout << "Testing ECB 128-bit decryption..." << std::endl;
	std::vector<uint8_t> result;
	ecb128_.decrypt(cipher_flow128_, result);

	assert(result == plain_flow128_);
	std::cout << "ECB 128-bit decryption test passed successfully!" << std::endl;
}

void ECBTest::assert_encrypt64() {
	std::cout << "Testing ECB 64-bit encryption..." << std::endl;
	std::vector<uint8_t> result;
	ecb64_.encrypt(plain_flow64_, result);

	assert(result == cipher_flow64_);
	std::cout << "ECB 64-bit encryption test passed successfully!" << std::endl;
}

void ECBTest::assert_decrypt64() {
	std::cout << "Testing ECB 64-bit decryption..." << std::endl;
	std::vector<uint8_t> result;
	ecb64_.decrypt(cipher_flow64_, result);

	assert(result == plain_flow64_);
	std::cout << "ECB 64-bit decryption test passed successfully!" << std::endl;
}

void ECBTest::assert_all_functions() {
	std::cout << "\nRunning all ECB mode tests..." << std::endl;
	assert_encrypt128();
	assert_decrypt128();
	
	assert_encrypt64();
	assert_decrypt64();
	std::cout << "All ECB mode tests completed successfully!" << std::endl;
}