#include <cassert>
#include "KExp15Test.h"
#include <iostream>

KExp15Test::KExp15Test() : kexp15_magma_(), kexp15_kuznyechik_() {
}

void KExp15Test::assert_export_key_magma() {
	std::cout << "Testing KExp15 Magma key export..." << std::endl;
	std::vector<uint8_t> kexp;
	kexp15_magma_.export_key(key_, k_mac_, k_enc_, iv_magma_, kexp);

	assert(kexp == kexp_magma_);
	std::cout << "KExp15 Magma key export test passed successfully!" << std::endl;
}

void KExp15Test::assert_export_key_kuznyechik() {
	std::cout << "Testing KExp15 Kuznyechik key export..." << std::endl;
	std::vector<uint8_t> kexp;
	kexp15_kuznyechik_.export_key(key_, k_mac_, k_enc_, iv_kuznyechik_, kexp);

	assert(kexp == kexp_kuznyechik_);
	std::cout << "KExp15 Kuznyechik key export test passed successfully!" << std::endl;
}

void KExp15Test::assert_import_key_magma() {
	std::cout << "Testing KExp15 Magma key import..." << std::endl;
	std::vector<uint8_t> k;
	kexp15_magma_.import_key(kexp_magma_, k_mac_, k_enc_, iv_magma_, k);

	assert(k == key_);
	std::cout << "KExp15 Magma key import test passed successfully!" << std::endl;
}

void KExp15Test::assert_import_key_kuznyechik() {
	std::cout << "Testing KExp15 Kuznyechik key import..." << std::endl;
	std::vector<uint8_t> k;
	kexp15_kuznyechik_.import_key(kexp_kuznyechik_, k_mac_, k_enc_, iv_kuznyechik_, k);

	assert(k == key_);
	std::cout << "KExp15 Kuznyechik key import test passed successfully!" << std::endl;
}

void KExp15Test::assert_all_functions() {
	std::cout << "\nRunning all KExp15 tests..." << std::endl;
	assert_export_key_magma();
	assert_export_key_kuznyechik();
	assert_import_key_magma();
	assert_import_key_kuznyechik();
	std::cout << "All KExp15 tests completed successfully!" << std::endl;
}