#include <algorithm>
#include "Magma.h"

    // numbers passes to methods as array of bytes in big-endian (as to read) order

    const std::vector<std::vector<uint8_t >> Magma::pi = {
            {12, 4,  6,  2,  10, 5,  11, 9,  14, 8,  13, 7,  0,  3,  15, 1}, // pi_0
            {6,  8,  2,  3,  9,  10, 5,  12, 1,  14, 4,  7,  11, 13, 0,  15}, // pi_1
            {11, 3,  5,  8,  2,  15, 10, 13, 14, 1,  7,  4,  12, 9,  6,  0}, // pi_2
            {12, 8,  2,  1,  13, 4,  15, 6,  7,  0,  10, 5,  3,  14, 9,  11}, // pi_3
            {7,  15, 5,  10, 8,  1,  6,  13, 0,  9,  3,  14, 11, 4,  2,  12}, // pi_4
            {5,  13, 15, 6,  9,  2,  12, 10, 11, 7,  8,  1,  4,  3,  14, 0}, // pi_5
            {8,  14, 2,  5,  6,  9,  1,  12, 15, 4,  11, 0,  13, 10, 3,  7}, // pi_6
            {1,  7,  14, 13, 0,  5,  8,  3,  4,  15, 10, 6,  9,  12, 11, 2}  // pi_7
    };

    void Magma::k_expand(const std::array<uint8_t, byte_block_size * 4>& key) {
        // choice of block in key
        for (int i = 0; i < 8; ++i) {
            // choice of iter_key index for current key block
            for (int j = 0; j < 3; ++j) {
                std::copy(key.begin() + i * 4, key.begin() + (i * 4 + 4), iter_keys_[i + (8 * j)].begin());
            }
            std::copy(key.begin() + i * 4, key.begin() + (i * 4 + 4), iter_keys_[31 - i].begin());
        }
    }

    void Magma::t_transform(const std::array<uint8_t, half_block_size>& src, std::array<uint8_t, 4>& dst) {
        // for all bytes in 32-bit word
        for (int i = 0; i < half_block_size; ++i) {
            uint8_t currByteBigHalf = src[i] >> 4;
            uint8_t currByteLittleHalf = src[i] & 0xF;

            // big endian order of input parameter
            uint8_t afterPiBigHalf = Magma::pi[7 - i * 2][currByteBigHalf];
            uint8_t afterPiLittleHalf = Magma::pi[7 - i * 2 - 1][currByteLittleHalf];

            uint8_t to_add = 0;
            to_add |= (afterPiBigHalf << 4);
            to_add |= afterPiLittleHalf;
            dst[i] = to_add;
        }
    }


    void Magma::g_transform(const std::array<uint8_t, half_block_size>& src,
        const std::array<uint8_t, half_block_size>& key,
        std::array<uint8_t, half_block_size>& dst) {
        // storage to prevent partial change of a
        std::array<uint8_t, half_block_size> intermediate_storage = {};
        uint8_t carry = 0;
        for (int i = 3; i >= 0; --i) {
            uint16_t total = src[i] + key[i] + carry;
            intermediate_storage[i] = total & 0xFF;
            carry = (total >> 8) & 0xFF;
        }

        t_transform(intermediate_storage, intermediate_storage);

        dst[0] = (intermediate_storage[1] << 3) | (intermediate_storage[2] >> 5);
        dst[1] = (intermediate_storage[2] << 3) | (intermediate_storage[3] >> 5);
        dst[2] = (intermediate_storage[3] << 3) | (intermediate_storage[0] >> 5);
        dst[3] = (intermediate_storage[0] << 3) | (intermediate_storage[1] >> 5);
    }

    void Magma::G_transform(const std::array<uint8_t, 4>& a1_src,
        const std::array<uint8_t, 4>& a0_src,
        const std::array<uint8_t, 4>& key,
        std::array<uint8_t, 4>& a1_dst,
        std::array<uint8_t, 4>& a0_dst) {
        std::array<uint8_t, half_block_size> intermediate_storage = {};
        g_transform(a0_src, key, intermediate_storage);
        for (int i = 0; i < 4; ++i) {
            intermediate_storage[i] ^= a1_src[i];
        }
        std::copy(a0_src.begin(), a0_src.end(), a1_dst.begin());
        std::copy(intermediate_storage.begin(), intermediate_storage.end(), a0_dst.begin());
    }

    void Magma::G_star_transform(const std::array<uint8_t, 4>& a1_src,
        const std::array<uint8_t, 4>& a0_src,
        const std::array<uint8_t, 4>& key,
        std::array<uint8_t, Magma::byte_block_size>& dst) {
        std::array<uint8_t, half_block_size> tmp_a1 = {};
        std::array<uint8_t, half_block_size> tmp_a0 = {};
        G_transform(a1_src, a0_src, key, tmp_a1, tmp_a0);
        for (int i = 0; i < 4; ++i) {
            dst[i] = tmp_a0[i];
            dst[4 + i] = tmp_a1[i];
        }
    }

    Magma::Magma() {
        iter_keys_ = {};
    }

    Magma::Magma(const std::array<uint8_t, byte_block_size * 4>& key) {
        iter_keys_ = {};
        k_expand(key);
    }

    void Magma::refresh_iter_keys(const std::array<uint8_t, byte_block_size * 4>& new_key) {
        iter_keys_ = {};
        k_expand(new_key);
    }

    std::array<std::array<uint8_t, Magma::half_block_size>, Magma::iter_keys_count> Magma::get_iter_keys() {
        return { iter_keys_ };
    }

    void Magma::encrypt(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst) {
        if (iter_keys_.empty()) {
            throw "Key must be providen. Required to call method refresh_iter_keys(key) ";
        }

        if (src.empty()) {
            return;
        }

        std::array<uint8_t, half_block_size> a1 = {};
        std::array<uint8_t, half_block_size> a0 = {};
        for (int i = 0; i < 4; ++i) {
            a1[i] = src[i];
            a0[i] = src[4 + i];
        }

        for (int i = 0; i < iter_keys_.size() - 1; ++i) {
            G_transform(a1, a0, iter_keys_[i], a1, a0);
        }
        G_star_transform(a1, a0, iter_keys_[31], dst);
    }

    void Magma::decrypt(const std::array<uint8_t, byte_block_size>& src,
        std::array<uint8_t, byte_block_size>& dst) {
        if (iter_keys_.empty()) {
            throw "Key must be providen. Required to call method refresh_iter_keys(key) ";
        }

        if (src.empty()) {
            return;
        }

        std::array<uint8_t, half_block_size> a1 = {};
        std::array<uint8_t, half_block_size> a0 = {};
        for (int i = 0; i < 4; ++i) {
            a1[i] = src[i];
            a0[i] = src[4 + i];
        }

        for (int i = 31; i > 0; --i) {
            G_transform(a1, a0, iter_keys_[i], a1, a0);
        }
        G_star_transform(a1, a0, iter_keys_[0], dst);
    }
