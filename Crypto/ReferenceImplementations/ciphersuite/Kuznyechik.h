#ifndef REFERENCEIMPLEMENTATIONS_KUZNYECHIK_H
#define REFERENCEIMPLEMENTATIONS_KUZNYECHIK_H

#include "../test_forward_declarations.h"
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include "../../GOSTTest/ciphersuite/KuznyechikTest.h"

class KuznyechikTest;

class Kuznyechik {

public:

    static const size_t byte_block_size = 16;

    static const size_t round_keys_count = 10;

    Kuznyechik();

    Kuznyechik(const std::array<uint8_t, byte_block_size * 2>& key);

    void encrypt(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst);

    void decrypt(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst);

    std::array<std::array<uint8_t, byte_block_size>, round_keys_count> get_iter_keys();

    void refresh_iter_keys(const std::array<uint8_t, byte_block_size * 2>& new_key);

    friend class GOSTTest::KuznyechikTest;

    // chosen: friend class для тестирования

private:

    static const std::vector<uint8_t> pi;

    static const std::vector<uint8_t> inverse_pi;

    std::array<std::array<uint8_t, byte_block_size>, round_keys_count> iter_keys_;

    void X_transform(const std::array<uint8_t, byte_block_size>& src,
        const std::array<uint8_t, byte_block_size>& key,
        std::array<uint8_t, byte_block_size>& dst);

    void S_transform(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst);

    void S_inverse_transform(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst);

    void R_transform(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst);

    void R_inverse_transform(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst);

    void L_transform(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst);

    void L_inverse_transform(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst);

    void F_transform(const std::array<uint8_t, byte_block_size>& a1_src,
        const std::array<uint8_t, byte_block_size>& a0_src,
        const std::array<uint8_t, byte_block_size>& key,
        std::array<uint8_t, byte_block_size>& a1_dst,
        std::array<uint8_t, byte_block_size>& a0_dst);

    void k_expand(const std::array<uint8_t, byte_block_size * 2>& key,
        std::array<std::array<uint8_t, byte_block_size>, round_keys_count>& dst);

    uint8_t gf_multiply(uint8_t a, uint8_t b);

    uint8_t l_transform(const std::array<uint8_t, byte_block_size>& word);
};

#endif //REFERENCEIMPLEMENTATIONS_KUZNYECHIK_H
