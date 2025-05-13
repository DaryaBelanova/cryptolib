#include <cassert>
#include "MagmaTest.h"
#include <iostream>

MagmaTest::MagmaTest() : magma_(key_) {
}

void MagmaTest::assert_t_transform() {
    std::cout << "Testing Magma T-transformation..." << std::endl;
    std::array<uint8_t, Magma::half_block_size> result = {};

    magma_.t_transform(t_input1_, result);
    assert(result == t_result1_);

    magma_.t_transform(result, result);
    assert(result == t_result2_);

    magma_.t_transform(result, result);
    assert(result == t_result3_);

    magma_.t_transform(result, result);
    assert(result == t_result4_);
    std::cout << "Magma T-transformation test passed successfully!" << std::endl;
}

void MagmaTest::assert_g_transform() {
    std::cout << "Testing Magma G-transformation..." << std::endl;
    std::array<uint8_t, Magma::half_block_size> result = {};

    magma_.g_transform(g_input1_, g_key1_, result);
    assert(result == g_result1_);

    magma_.g_transform(g_key1_,result, result);
    assert(result == g_result2_);

    magma_.g_transform(g_result1_, result, result);
    assert(result == g_result3_);

    magma_.g_transform(g_result2_, result, result);
    assert(result == g_result4_);
    std::cout << "Magma G-transformation test passed successfully!" << std::endl;
}

void MagmaTest::assert_k_expand() {
    std::cout << "Testing Magma key expansion..." << std::endl;
    auto iter_keys = magma_.get_iter_keys();

    // choice of block of large key
    for (int i = 0; i < 8; ++i) {
        // choice of index of iter_key that equal current key_block
        for (int j = 0; j < 3; ++j) {
            assert(iter_keys[i + j * 8] == valid_different_iter_keys_[i]);
        }
        // last reversed part of indexes
        assert(iter_keys[31- i] == valid_different_iter_keys_[i]);
    }
    std::cout << "Magma key expansion test passed successfully!" << std::endl;
}

void MagmaTest::assert_encrypt() {
    std::cout << "Testing Magma encryption..." << std::endl;
    std::array<uint8_t, Magma::byte_block_size> encrypted = {};
    magma_.encrypt(a_, encrypted);

    assert(encrypted == b_);
    std::cout << "Magma encryption test passed successfully!" << std::endl;
}

void MagmaTest::assert_encrypt_G_transform_step_by_step() {
    std::cout << "Testing Magma step-by-step G-transformation encryption..." << std::endl;
    std::array<uint8_t, Magma::half_block_size> a1 = {0xfe, 0xdc, 0xba, 0x98};
    std::array<uint8_t, Magma::half_block_size> a0 = {0x76, 0x54, 0x32, 0x10};

    for (int i = 0; i < 31; ++i) {
        magma_.G_transform(a1, a0, magma_.get_iter_keys()[i], a1, a0);
        assert(a1 == MagmaTest::iter_a1_a0_[i] &&
               a0 == MagmaTest::iter_a1_a0_[i + 1]);
    }
    std::cout << "Magma step-by-step G-transformation encryption test passed successfully!" << std::endl;
}

void MagmaTest::assert_decrypt() {
    std::cout << "Testing Magma decryption..." << std::endl;
    std::array<uint8_t, Magma::byte_block_size> decrypted = {};
    magma_.decrypt(b_, decrypted);

    assert(decrypted == a_);
    std::cout << "Magma decryption test passed successfully!" << std::endl;
}

void MagmaTest::assert_decrypt_G_transform_step_by_step() {
    std::cout << "Testing Magma step-by-step G-transformation decryption..." << std::endl;
    std::array<uint8_t, Magma::half_block_size> b1 = {0x4e, 0xe9, 0x01, 0xe5};
    std::array<uint8_t, Magma::half_block_size> b0 = {0xc2, 0xd8, 0xca, 0x3d};

    for (int i = 0; i < 31; ++i) {
        magma_.G_transform(b1, b0, magma_.get_iter_keys()[31 - i], b1, b0);
        assert(b1 == iter_a1_a0_[31 - i] &&
               b0 == iter_a1_a0_[30 - i]);
    }
    std::cout << "Magma step-by-step G-transformation decryption test passed successfully!" << std::endl;
}

void MagmaTest::assert_all_functions() {
    std::cout << "\nRunning all Magma tests..." << std::endl;
    assert_t_transform();
    assert_g_transform();
    assert_k_expand();
    assert_encrypt();
    assert_encrypt_G_transform_step_by_step();
    assert_decrypt();
    assert_decrypt_G_transform_step_by_step();
    std::cout << "All Magma tests completed successfully!" << std::endl;
}