#include <array>
#include "Kuznyechik.h"


    // numbers passes to methods as array of bytes in big-endian (as to read) order

    const std::vector<uint8_t> Kuznyechik::pi = {
            252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
            119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24, 101,
            90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106, 143,
            160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242, 42,
            104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156,
            183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178,
            177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
            245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
            222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30, 0,
            98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140, 163,
            165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136,
            217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133,
            97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89, 166,
            116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182
    };

    const std::vector<uint8_t> Kuznyechik::inverse_pi = {
            165, 45, 50, 143, 14, 48, 56, 192, 84, 230, 158, 57, 85, 126, 82, 145, 100,
            3, 87, 90, 28, 96, 7, 24, 33, 114, 168, 209, 41, 198, 164, 63, 224, 39, 141,
            12, 130, 234, 174, 180, 154, 99, 73, 229, 66, 228, 21, 183, 200, 6, 112,
            157, 65, 117, 25, 201, 170, 252, 77, 191, 42, 115, 132, 213, 195, 175, 43, 134,
            167, 177, 178, 91, 70, 211, 159, 253, 212, 15, 156, 47, 155, 67, 239, 217, 121,
            182, 83, 127, 193, 240, 35, 231, 37, 94, 181, 30, 162, 223, 166, 254, 172,
            34, 249, 226, 74, 188, 53, 202, 238, 120, 5, 107, 81, 225, 89, 163, 242, 113,
            86, 17, 106, 137, 148, 101, 140, 187, 119, 60, 123, 40, 171, 210, 49, 222, 196,
            95, 204, 207, 118, 44, 184, 216, 46, 54, 219, 105, 179, 20, 149, 190, 98,
            161, 59, 22, 102, 233, 92, 108, 109, 173, 55, 97, 75, 185, 227, 186, 241, 160,
            133, 131, 218, 71, 197, 176, 51, 250, 150, 111, 110, 194, 246, 80, 255, 93, 169,
            142, 23, 27, 151, 125, 236, 88, 247, 31, 251, 124, 9, 13, 122, 103, 69, 135, 220,
            232, 79, 29, 78, 4, 235, 248, 243, 62, 61, 189, 138, 136, 221, 205, 11, 19, 152,
            2, 147, 128, 144, 208, 36, 52, 203, 237, 244, 206, 153, 16, 68, 64, 146, 58, 1, 38, 18,
            26, 72, 104, 245, 129, 139, 199, 214, 32, 10, 8, 0, 76, 215, 116
    };

    void Kuznyechik::X_transform(const std::array<uint8_t, byte_block_size>& src, const std::array<uint8_t, byte_block_size>& key, std::array<uint8_t, byte_block_size>& dst) {
        for (int i = 0; i < Kuznyechik::byte_block_size; ++i) {
            dst[i] = src[i] ^ key[i];
        }
    }

    void Kuznyechik::S_transform(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        for (int i = 0; i < Kuznyechik::byte_block_size; ++i) {
            dst[i] = Kuznyechik::pi[src[i]];
        }
    }

    void Kuznyechik::S_inverse_transform(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        for (int i = 0; i < Kuznyechik::byte_block_size; ++i) {
            dst[i] = Kuznyechik::inverse_pi[src[i]];
        }
    }

    uint8_t Kuznyechik::gf_multiply(uint8_t a, uint8_t b) {
        uint16_t result = 0;
        uint8_t hi_bit_set;
        for (int i = 0; i < 8; ++i) {
            if (b & 1) {
                result ^= a;
            }
            hi_bit_set = (a & 0x80);
            a <<= 1;
            if (hi_bit_set) {
                a ^= 0b11000011;
            }
            b >>= 1;
        }
        return result;
    }

    uint8_t Kuznyechik::l_transform(const std::array<uint8_t, byte_block_size>& word) {
        std::vector<uint8_t> linear_coefficients{
                148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
        };
        uint8_t sum = 0;
        for (int i = 0; i < Kuznyechik::byte_block_size; ++i) {
            sum ^= gf_multiply(word[i], linear_coefficients[i]);
        }
        return sum;
    }

    void Kuznyechik::R_transform(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        uint8_t first_byte = l_transform(src);
        std::copy(src.begin(), src.end() - 1, dst.begin() + 1);
        dst[0] = first_byte;
    }

    void Kuznyechik::R_inverse_transform(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        std::array<uint8_t, byte_block_size> to_pass_in_l = {};
        std::copy(src.begin() + 1, src.end(), to_pass_in_l.begin());
        to_pass_in_l[15] = src[0];

        std::copy(src.begin() + 1, src.end(), dst.begin());
        dst[15] = l_transform(to_pass_in_l);
    }

    void Kuznyechik::L_transform(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        std::copy(src.begin(), src.end(), dst.begin());
        for (int i = 0; i < 16; ++i) {
            R_transform(dst, dst);
        }
    }

    void Kuznyechik::L_inverse_transform(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        std::copy(src.begin(), src.end(), dst.begin());
        for (int i = 0; i < 16; ++i) {
            R_inverse_transform(dst, dst);
        }
    }

    void Kuznyechik::F_transform(const std::array<uint8_t, byte_block_size>& a1_src,
        const std::array<uint8_t, byte_block_size>& a0_src,
        const std::array<uint8_t, byte_block_size>& key,
        std::array<uint8_t, byte_block_size>& a1_dst,
        std::array<uint8_t, byte_block_size>& a0_dst) {
        // storage of LSX[key](a1) to prevent rewriting in case of pass the same vector as k_exp parameters
        std::array<uint8_t, byte_block_size> intermediate_storage = {};
        X_transform(a1_src, key, intermediate_storage);
        S_transform(intermediate_storage, intermediate_storage);
        L_transform(intermediate_storage, intermediate_storage);

        for (int i = 0; i < Kuznyechik::byte_block_size; ++i) {
            intermediate_storage[i] ^= a0_src[i];
        }
        // a1 -> result a0
        std::copy(a1_src.begin(), a1_src.end(), a0_dst.begin());
        // transformed -> new a1
        std::copy(intermediate_storage.begin(), intermediate_storage.end(), a1_dst.begin());
    }

    void Kuznyechik::k_expand(const std::array<uint8_t, byte_block_size * 2>& key, std::array<std::array<uint8_t, byte_block_size>, round_keys_count>& dst) {
        std::array<uint8_t, Kuznyechik::byte_block_size> k1 = {};
        std::array<uint8_t, Kuznyechik::byte_block_size> k2 = {};
        std::copy(key.begin(), key.begin() + 16, k1.begin());
        std::copy(key.begin() + 16, key.end(), k2.begin());

        dst[0] = k1;
        dst[1] = k2;

        std::array<uint8_t, byte_block_size> curr_const = {};
        for (int i = 1; i <= 4; ++i) {
            for (int j = 1; j <= 8; ++j) {
                curr_const.fill(0);
                curr_const[15] = 8 * (i - 1) + j;

                L_transform(curr_const, curr_const);
                F_transform(k1, k2, curr_const, k1, k2);
            }
            dst[2 * i] = k1;
            dst[2 * i + 1] = k2;
        }
    }

    Kuznyechik::Kuznyechik() {
        iter_keys_ = {};
    }

    Kuznyechik::Kuznyechik(const std::array<uint8_t, byte_block_size * 2>& key) {
        iter_keys_ = {};
        k_expand(key, iter_keys_);
    }

    void Kuznyechik::refresh_iter_keys(const std::array<uint8_t, byte_block_size * 2>& new_key) {
        iter_keys_ = {};
        k_expand(new_key, iter_keys_);
    }

    void Kuznyechik::encrypt(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        if (iter_keys_.empty()) {
            throw "Key must be providen. Required to call method refresh_iter_keys(key) ";
        }

        if (src.empty()) {
            return;
        }

        std::copy(src.begin(), src.end(), dst.begin());
        for (int i = 0; i < 9; ++i) {
            X_transform(dst, iter_keys_[i], dst);
            S_transform(dst, dst);
            L_transform(dst, dst);
        }
        X_transform(dst, iter_keys_[9], dst);
    }

    void Kuznyechik::decrypt(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst) {
        if (iter_keys_.empty()) {
            throw "Key must be providen. Required to call method refresh_iter_keys(key) ";
        }

        if (src.empty()) {
            return;
        }

        std::copy(src.begin(), src.end(), dst.begin());
        for (int i = 0; i < 9; ++i) {
            X_transform(dst, iter_keys_[9 - i], dst);
            L_inverse_transform(dst, dst);
            S_inverse_transform(dst, dst);
        }
        X_transform(dst, iter_keys_[0], dst);
    }

    std::array<std::array<uint8_t, Kuznyechik::byte_block_size>, Kuznyechik::round_keys_count> Kuznyechik::get_iter_keys() {
        return { iter_keys_ };
    }
