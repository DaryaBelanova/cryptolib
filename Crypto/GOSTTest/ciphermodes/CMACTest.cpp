#include <cassert>
#include "CMACTest.h"
#include <algorithm>
#include <iostream>

CMACTest::CMACTest() : alg128_(key128_), alg64_(key64_), cmac128_(alg128_, s128_), cmac64_(alg64_, s64_) {
}

void CMACTest::assert_k1_128() {
    std::cout << "Testing CMAC 128-bit K1 generation..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> result = {};

    cmac128_.get_k1(result);

    assert(result == k1_128_);
    std::cout << "CMAC 128-bit K1 generation test passed successfully!" << std::endl;
}

void CMACTest::assert_k2_128() {
    std::cout << "Testing CMAC 128-bit K2 generation..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> result = {};

    cmac128_.get_k2(result);

    assert(result == k2_128_);
    std::cout << "CMAC 128-bit K2 generation test passed successfully!" << std::endl;
}

void CMACTest::assert_update128() {
    std::cout << "Testing CMAC 128-bit update operation..." << std::endl;
    std::vector<uint8_t> result = {};

    cmac128_.update(plain_blocks128_[0]);
    assert(cmac128_.curr_state == input_blocks128_[0]);

    cmac128_.update(plain_blocks128_[1]);
    assert(cmac128_.curr_state == input_blocks128_[1]);

    cmac128_.update(plain_blocks128_[2]);
    assert(cmac128_.curr_state == input_blocks128_[2]);

    cmac128_.update(plain_blocks128_[3]);
    std::array<uint8_t, Kuznyechik::byte_block_size> before_key = {};
    std::copy(input_blocks128_[3].begin(), input_blocks128_[3].end(), before_key.begin());
    for (int i = 0; i < Kuznyechik::byte_block_size; i++) {
        before_key[i] ^= k1_128_[i];
    }
    assert(cmac128_.curr_state == before_key);
    std::cout << "CMAC 128-bit update operation test passed successfully!" << std::endl;
}

void CMACTest::assert_finalize128() {
    std::cout << "Testing CMAC 128-bit finalization..." << std::endl;
    std::vector<uint8_t> result = {};
    cmac128_.finalize(result);

    assert(result == mac128_);
    std::cout << "CMAC 128-bit finalization test passed successfully!" << std::endl;
}

void CMACTest::assert_verify128() {
    std::cout << "Testing CMAC 128-bit verification..." << std::endl;
    assert(cmac128_.verify(mac128_));
    std::cout << "CMAC 128-bit verification test passed successfully!" << std::endl;
}

void CMACTest::assert_refresh128() {
    std::cout << "Testing CMAC 128-bit refresh..." << std::endl;
    cmac128_.refresh(64);
    
    assert(cmac128_.s_ == 8);
    assert(std::all_of(cmac128_.curr_state.begin(), cmac128_.curr_state.end(),
        [](uint8_t value) {return value == 0; }));
    std::cout << "CMAC 128-bit refresh test passed successfully!" << std::endl;
}

void CMACTest::assert_k1_64() {
    std::cout << "Testing CMAC 64-bit K1 generation..." << std::endl;
    std::array<uint8_t, Magma::byte_block_size> result = {};

    cmac64_.get_k1(result);

    assert(result == k1_64_);
    std::cout << "CMAC 64-bit K1 generation test passed successfully!" << std::endl;
}

void CMACTest::assert_k2_64() {
    std::cout << "Testing CMAC 64-bit K2 generation..." << std::endl;
    std::array<uint8_t, Magma::byte_block_size> result = {};

    cmac64_.get_k2(result);

    assert(result == k2_64_);
    std::cout << "CMAC 64-bit K2 generation test passed successfully!" << std::endl;
}

void CMACTest::assert_update64() {
    std::cout << "Testing CMAC 64-bit update operation..." << std::endl;
    std::vector<uint8_t> result = {};

    cmac64_.update(plain_blocks64_[0]);
    assert(cmac64_.curr_state == input_blocks64_[0]);

    cmac64_.update(plain_blocks64_[1]);
    assert(cmac64_.curr_state == input_blocks64_[1]);

    cmac64_.update(plain_blocks64_[2]);
    assert(cmac64_.curr_state == input_blocks64_[2]);

    cmac64_.update(plain_blocks64_[3]);
    std::array<uint8_t, Magma::byte_block_size> before_key = {};
    std::copy(input_blocks64_[3].begin(), input_blocks64_[3].end(), before_key.begin());
    for (int i = 0; i < Magma::byte_block_size; i++) {
        before_key[i] ^= k1_64_[i];
    }
    assert(cmac64_.curr_state == before_key);
    std::cout << "CMAC 64-bit update operation test passed successfully!" << std::endl;
}

void CMACTest::assert_finalize64() {
    std::cout << "Testing CMAC 64-bit finalization..." << std::endl;
    std::vector<uint8_t> result = {};
    cmac64_.finalize(result);

    assert(result == mac64_);
    std::cout << "CMAC 64-bit finalization test passed successfully!" << std::endl;
}

void CMACTest::assert_verify64() {
    std::cout << "Testing CMAC 64-bit verification..." << std::endl;
    assert(cmac64_.verify(mac64_));
    std::cout << "CMAC 64-bit verification test passed successfully!" << std::endl;
}

void CMACTest::assert_refresh64() {
    std::cout << "Testing CMAC 64-bit refresh..." << std::endl;
    cmac64_.refresh(32);

    assert(cmac64_.s_ == 4);
    assert(std::all_of(cmac64_.curr_state.begin(), cmac64_.curr_state.end(),
        [](uint8_t value) {return value == 0; }));
    std::cout << "CMAC 64-bit refresh test passed successfully!" << std::endl;
}

// functions depend on the result of the previous one. The order of functions call is important
void CMACTest::assert_all_functions() {
    std::cout << "\nRunning all CMAC tests..." << std::endl;
    assert_k1_128();
    assert_k2_128();
    assert_update128();
    assert_finalize128();
    assert_verify128();
    assert_refresh128();
    
    assert_k1_64();
    assert_k2_64();
    assert_update64();
    assert_finalize64();
    assert_verify64();
    assert_refresh64();
    std::cout << "All CMAC tests completed successfully!" << std::endl;
}