#include <cassert>
#include "KuznyechikTest.h"
#include <iostream>

KuznyechikTest::KuznyechikTest() : kuznyechik_(key_) {
}

void KuznyechikTest::assert_S_transform() {
    std::cout << "Testing Kuznyechik S-transformation..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> result = {};

    kuznyechik_.S_transform(KuznyechikTest::S_input1, result);
    assert(result == S_result1);

    kuznyechik_.S_transform(result, result);
    assert(result == S_result2);

    kuznyechik_.S_transform(result, result);
    assert(result == S_result3);

    kuznyechik_.S_transform(result, result);
    assert(result == S_result4);
    std::cout << "Kuznyechik S-transformation test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_R_transform() {
    std::cout << "Testing Kuznyechik R-transformation..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> result = {};

    kuznyechik_.R_transform(R_input1, result);
    assert(result == R_result1);

    kuznyechik_.R_transform(result, result);
    assert(result == R_result2);

    kuznyechik_.R_transform(result, result);
    assert(result == R_result3);

    kuznyechik_.R_transform(result, result);
    assert(result == R_result4);
    std::cout << "Kuznyechik R-transformation test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_L_transform()  {
    std::cout << "Testing Kuznyechik L-transformation..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> result = {};

    kuznyechik_.L_transform(L_input1, result);
    assert(result == L_result1);

    kuznyechik_.L_transform(result, result);
    assert(result == L_result2);

    kuznyechik_.L_transform(result, result);
    assert(result == L_result3);

    kuznyechik_.L_transform(result, result);
    assert(result == L_result4);
    std::cout << "Kuznyechik L-transformation test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_first_8_iter_consts() {
    std::cout << "Testing Kuznyechik first 8 iteration constants..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> curr_const = {};
    for (int i = 0; i < 8; ++i) {
        curr_const = {};
        curr_const[15] = i + 1;
        kuznyechik_.L_transform(curr_const, curr_const);
        assert(curr_const == first_8_iter_consts_[i]);
    }
    std::cout << "Kuznyechik first 8 iteration constants test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_lsx_in_k_expand() {
    std::cout << "Testing Kuznyechik LSX transformations in key expansion..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> c1 = {0x6e, 0xa2, 0x76, 0x72, 0x6c, 0x48, 0x7a, 0xb8, 0x5d, 0x27, 0xbd, 0x10, 0xdd, 0x84, 0x94, 0x01};
    std::array<uint8_t, Kuznyechik::byte_block_size> k = {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};

    kuznyechik_.X_transform(k, c1, k);
    assert(k == X_result_);

    kuznyechik_.S_transform(k, k);
    assert(k == SX_result_);

    kuznyechik_.L_transform(k, k);
    assert(k == LSX_result_);
    std::cout << "Kuznyechik LSX transformations in key expansion test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_kuz_k_expand() {
    std::cout << "Testing Kuznyechik key expansion..." << std::endl;
    auto iter_keys = kuznyechik_.get_iter_keys();

    for (int i = 0; i < 8; ++i) {
        assert(iter_keys[i] == kuznyechik_valid_iter_keys_[i]);
    }
    std::cout << "Kuznyechik key expansion test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_kuz_k_expand_step_by_step()  {
    std::cout << "Testing Kuznyechik step-by-step key expansion..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> k1 = {0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    std::array<uint8_t, Kuznyechik::byte_block_size> k2 = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};

    for (int i = 0; i < 8; ++i) {
        kuznyechik_.F_transform(k1, k2, first_8_iter_consts_[i], k1, k2);
        assert(k1 == valid_expanded_keys_[i * 2]);
        assert(k2 == valid_expanded_keys_[i * 2 + 1]);
    }
    std::cout << "Kuznyechik step-by-step key expansion test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_kuz_encrypt() {
    std::cout << "Testing Kuznyechik encryption..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> encrypted = {};
    kuznyechik_.encrypt(a_, encrypted);

    assert(encrypted == b_);
    std::cout << "Kuznyechik encryption test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_encrypt_step_by_step() {
    std::cout << "Testing Kuznyechik step-by-step encryption..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> lsx = {};

    kuznyechik_.X_transform(a_, kuznyechik_valid_iter_keys_[0], lsx);
    assert(lsx == valid_X_);

    kuznyechik_.S_transform(lsx, lsx);
    assert(lsx == valid_SX_);

    kuznyechik_.L_transform(lsx, lsx);
    assert(lsx == valid_first_LSX_);

    for (int i = 0; i < 8; ++i) {
        kuznyechik_.X_transform(lsx, kuznyechik_valid_iter_keys_[i + 1], lsx);
        kuznyechik_.S_transform(lsx, lsx);
        kuznyechik_.L_transform(lsx, lsx);
        assert(lsx == valid_LSX_[i]);
    }

    kuznyechik_.X_transform(lsx, kuznyechik_valid_iter_keys_[9], lsx);
    assert(lsx == b_);
    std::cout << "Kuznyechik step-by-step encryption test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_kuz_decrypt() {
    std::cout << "Testing Kuznyechik decryption..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> decrypted = {};
    kuznyechik_.decrypt(b_, decrypted);

    assert(decrypted == a_);
    std::cout << "Kuznyechik decryption test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_decrypt_step_by_step()  {
    std::cout << "Testing Kuznyechik step-by-step decryption..." << std::endl;
    std::array<uint8_t, Kuznyechik::byte_block_size> s_inv_l_inv_x = {};

    kuznyechik_.X_transform(b_, kuznyechik_valid_iter_keys_[9], s_inv_l_inv_x);
    assert(s_inv_l_inv_x == valid_X_inv_);

    kuznyechik_.L_inverse_transform(s_inv_l_inv_x, s_inv_l_inv_x);
    assert(s_inv_l_inv_x == valid_L_inv_X_);

    kuznyechik_.S_inverse_transform(s_inv_l_inv_x, s_inv_l_inv_x);
    assert(s_inv_l_inv_x == valid_first_S_inv_L_inv_X_);

    for (int i = 0; i < 8; ++i) {
        kuznyechik_.X_transform(s_inv_l_inv_x, kuznyechik_valid_iter_keys_[8 - i], s_inv_l_inv_x);
        kuznyechik_.L_inverse_transform(s_inv_l_inv_x, s_inv_l_inv_x);
        kuznyechik_.S_inverse_transform(s_inv_l_inv_x, s_inv_l_inv_x);
        assert(s_inv_l_inv_x == valid_S_inv_L_inv_X_[i]);
    }

    kuznyechik_.X_transform(s_inv_l_inv_x, kuznyechik_valid_iter_keys_[0], s_inv_l_inv_x);
    assert(s_inv_l_inv_x == a_);
    std::cout << "Kuznyechik step-by-step decryption test passed successfully!" << std::endl;
}

void KuznyechikTest::assert_all_functions() {
    std::cout << "\nRunning all Kuznyechik tests..." << std::endl;
    assert_S_transform();
    assert_R_transform();
    assert_L_transform();
    assert_first_8_iter_consts();
    assert_lsx_in_k_expand();
    assert_kuz_k_expand() ;
    assert_kuz_k_expand_step_by_step();
    assert_kuz_encrypt() ;
    assert_encrypt_step_by_step();
    assert_kuz_decrypt() ;
    assert_decrypt_step_by_step() ;
    std::cout << "All Kuznyechik tests completed successfully!" << std::endl;
}