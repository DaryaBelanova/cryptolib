#include <cassert>
#include "KDFCMACTest.h"
#include <iostream>

KDFCMACTest::KDFCMACTest() : kdf_cmac_(key_) {
}

void KDFCMACTest::assert_get_k_mac_magma_ctr_cmac() {
	std::cout << "Testing KDF CMAC Magma CTR MAC key generation..." << std::endl;
	std::vector<uint8_t> k = {};
	kdf_cmac_.get_crisp_k_mac(label_macenc_, seqNum1_3_, CS1_, sourceIdentifier_, 512, k);

	assert(k == valid_k_mac_1_);
	std::cout << "KDF CMAC Magma CTR MAC key generation test passed successfully!" << std::endl;
}

void KDFCMACTest::assert_get_k_enc_magma_ctr_cmac() {
	std::cout << "Testing KDF CMAC Magma CTR encryption key generation..." << std::endl;
	std::vector<uint8_t> k = {};
	kdf_cmac_.get_crisp_k_enc(label_macenc_, seqNum1_3_, CS1_, sourceIdentifier_, 512, k);

	assert(k == valid_k_enc_1_);
	std::cout << "KDF CMAC Magma CTR encryption key generation test passed successfully!" << std::endl;
}

void KDFCMACTest::assert_get_k_mac_magma_null_cmac() {
	std::cout << "Testing KDF CMAC Magma NULL MAC key generation..." << std::endl;
	std::vector<uint8_t> k = {};
	kdf_cmac_.get_crisp_k_mac(label_macmac_, seqNum2_4_, CS2_, sourceIdentifier_, 256, k);

	assert(k == valid_k_mac_2_);
	std::cout << "KDF CMAC Magma NULL MAC key generation test passed successfully!" << std::endl;
}

void KDFCMACTest::assert_get_k_mac_magma_ctr_cmac8() {
	std::cout << "Testing KDF CMAC8 Magma CTR MAC key generation..." << std::endl;
	std::vector<uint8_t> k = {};
	kdf_cmac_.get_crisp_k_mac(label_macenc_, seqNum1_3_, CS3_, sourceIdentifier_, 512, k);

	assert(k == valid_k_mac_3_);
	std::cout << "KDF CMAC8 Magma CTR MAC key generation test passed successfully!" << std::endl;
}

void KDFCMACTest::assert_get_k_enc_magma_ctr_cmac8() {
	std::cout << "Testing KDF CMAC8 Magma CTR encryption key generation..." << std::endl;
	std::vector<uint8_t> k = {};
	kdf_cmac_.get_crisp_k_enc(label_macenc_, seqNum1_3_, CS3_, sourceIdentifier_, 512, k);

	assert(k == valid_k_enc_3_);
	std::cout << "KDF CMAC8 Magma CTR encryption key generation test passed successfully!" << std::endl;
}

void KDFCMACTest::assert_get_k_mac_magma_null_cmac8() {
	std::cout << "Testing KDF CMAC8 Magma NULL MAC key generation..." << std::endl;
	std::vector<uint8_t> k = {};
	kdf_cmac_.get_crisp_k_mac(label_macmac_, seqNum2_4_, CS4_, sourceIdentifier_, 256, k);

	assert(k == valid_k_mac_4_);
	std::cout << "KDF CMAC8 Magma NULL MAC key generation test passed successfully!" << std::endl;
}

void KDFCMACTest::assert_all_functions() {
	std::cout << "\nRunning all KDF CMAC tests..." << std::endl;
	assert_get_k_mac_magma_ctr_cmac();
	assert_get_k_enc_magma_ctr_cmac();
	assert_get_k_mac_magma_null_cmac();
	assert_get_k_mac_magma_ctr_cmac8();
	assert_get_k_enc_magma_ctr_cmac8();
	assert_get_k_mac_magma_null_cmac8();
	std::cout << "All KDF CMAC tests completed successfully!" << std::endl;
}
