#ifndef CRYPTOLIB_MAGMATEST_H
#define CRYPTOLIB_MAGMATEST_H

#include <cstdint>
#include <array>
#include "../../ReferenceImplementations/ciphersuite/Magma.h"

class MagmaTest {

public:

    MagmaTest();

    void assert_t_transform();

    void assert_g_transform();

    void assert_k_expand();

    void assert_encrypt();

    void assert_encrypt_G_transform_step_by_step();

    void assert_decrypt();

    void assert_decrypt_G_transform_step_by_step();

    void assert_all_functions();

private:

    static constexpr std::array<uint8_t, Magma::byte_block_size * 4> key_ = {0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77,
                                                                  0x66, 0x55, 0x44, 0x33,
                                                                  0x22, 0x11, 0x00, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5,
                                                                  0xf6, 0xf7, 0xf8, 0xf9,
                                                                  0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};
    Magma magma_;

    static constexpr std::array<std::array<uint8_t, 4>, 8> valid_different_iter_keys_ = {
            {{0xff, 0xee, 0xdd, 0xcc},
             {0xbb, 0xaa, 0x99, 0x88},
             {0x77, 0x66, 0x55, 0x44},
             {0x33, 0x22, 0x11, 0x00},
             {0xf0, 0xf1, 0xf2, 0xf3},
             {0xf4, 0xf5, 0xf6, 0xf7},
             {0xf8, 0xf9, 0xfa, 0xfb},
             {0xfc, 0xfd, 0xfe, 0xff}}
    };

    // for t_transform method
    static constexpr std::array<uint8_t, Magma::half_block_size> t_input1_ = {0xfd, 0xb9, 0x75, 0x31};
    static constexpr std::array<uint8_t, Magma::half_block_size> t_result1_ = {0x2a, 0x19, 0x6f, 0x34};
    static constexpr std::array<uint8_t, Magma::half_block_size> t_result2_ = {0xeb, 0xd9, 0xf0, 0x3a};
    static constexpr std::array<uint8_t, Magma::half_block_size> t_result3_ = {0xb0, 0x39, 0xbb, 0x3d};
    static constexpr std::array<uint8_t, Magma::half_block_size> t_result4_ = {0x68, 0x69, 0x54, 0x33};

    // for g_transform method
    static constexpr std::array<uint8_t, Magma::half_block_size> g_input1_ = {0xfe, 0xdc, 0xba, 0x98};
    static constexpr std::array<uint8_t, Magma::half_block_size> g_key1_ = {0x87, 0x65, 0x43, 0x21};
    static constexpr std::array<uint8_t, Magma::half_block_size> g_result1_ = {0xfd, 0xcb, 0xc2, 0x0c};
    static constexpr std::array<uint8_t, Magma::half_block_size> g_result2_ = {0x7e, 0x79, 0x1a, 0x4b};
    static constexpr std::array<uint8_t, Magma::half_block_size> g_result3_ = {0xc7, 0x65, 0x49, 0xec};
    static constexpr std::array<uint8_t, Magma::half_block_size> g_result4_ = {0x97, 0x91, 0xc8, 0x49};

    // for G_transform method
    static constexpr std::array<std::array<uint8_t, 4>, 32> iter_a1_a0_ = {
            {{0x76, 0x54, 0x32, 0x10}, // G[K1](a1, a0) result-2
             {0x28, 0xda, 0x3b, 0x14}, // G[K2]G[K1](a1, a0) result-1
             {0xb1, 0x43, 0x37, 0xa5}, // G[K2]G[K1](a1, a0) result-2
             {0x63, 0x3a, 0x7c, 0x68}, // G[K3]…G[K1](a1, a0) result-2
             {0xea, 0x89, 0xc0, 0x2c}, // G[K4]…G[K1](a1, a0) result-2
             {0x11, 0xfe, 0x72, 0x6d}, // G[K5]…G[K1](a1, a0) result-2
             {0xad, 0x03, 0x10, 0xa4}, // G[K6]…G[K1](a1, a0) result-2
             {0x37, 0xd9, 0x7f, 0x25}, // G[K7]…G[K1](a1, a0) result-2
             {0x46, 0x32, 0x46, 0x15}, // G[K8]…G[K1](a1, a0) result-2
             {0xce, 0x99, 0x5f, 0x2a}, // G[K9]…G[K1](a1, a0) result-2
             {0x93, 0xc1, 0xf4, 0x49}, // G[K10]…G[K1](a1, a0) result-2
             {0x48, 0x11, 0xc7, 0xad}, // G[K11]…G[K1](a1, a0) result-2
             {0xc4, 0xb3, 0xed, 0xca}, // G[K12]…G[K1](a1, a0) result-2
             {0x44, 0xca, 0x5c, 0xe1}, // G[K13]…G[K1](a1, a0) result-2
             {0xfe, 0xf5, 0x1b, 0x68}, // G[K14]…G[K1](a1, a0) result-2
             {0x20, 0x98, 0xcd, 0x86}, // G[K15]…G[K1](a1, a0) result-2
             {0x4f, 0x15, 0xb0, 0xbb}, // G[K16]…G[K1](a1, a0) result-2
             {0xe3, 0x28, 0x05, 0xbc}, // G[K17]…G[K1](a1, a0) result-2
             {0xe7, 0x11, 0x67, 0x22}, // G[K18]…G[K1](a1, a0) result-2
             {0x89, 0xca, 0xdf, 0x21}, // G[K19]…G[K1](a1, a0) result-2
             {0xba, 0xc8, 0x44, 0x4d}, // G[K20]…G[K1](a1, a0) result-2
             {0x11, 0x26, 0x3a, 0x21}, // G[K21]…G[K1](a1, a0) result-2
             {0x62, 0x54, 0x34, 0xc3}, // G[K22]…G[K1](a1, a0) result-2
             {0x80, 0x25, 0xc0, 0xa5}, // G[K23]…G[K1](a1, a0) result-2
             {0xb0, 0xd6, 0x65, 0x14}, // G[K24]…G[K1](a1, a0) result-2
             {0x47, 0xb1, 0xd5, 0xf4}, // G[K25]…G[K1](a1, a0) result-2
             {0xc7, 0x8e, 0x6d, 0x50}, // G[K26]…G[K1](a1, a0) result-2
             {0x80, 0x25, 0x1e, 0x99}, // G[K27]…G[K1](a1, a0) result-2
             {0x2b, 0x96, 0xec, 0xa6}, // G[K28]…G[K1](a1, a0) result-2
             {0x05, 0xef, 0x44, 0x01}, // G[K29]…G[K1](a1, a0) result-2
             {0x23, 0x9a, 0x45, 0x77}, // G[K30]…G[K1](a1, a0) result-2
             {0xc2, 0xd8, 0xca, 0x3d}}  // G[K31]…G[K1](a1, a0) result-2

    };

    static constexpr std::array<uint8_t, 8> a_ = {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10};

    static constexpr std::array<uint8_t, 8> b_ = {0x4e, 0xe9, 0x01, 0xe5, 0xc2, 0xd8, 0xca, 0x3d};
};


#endif //CRYPTOLIB_MAGMATEST_H
