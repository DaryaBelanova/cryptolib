#ifndef REFERENCEIMPLEMENTATIONS_MAGMA_H
#define REFERENCEIMPLEMENTATIONS_MAGMA_H

#include <vector>
#include <cstdint>
#include <string>
#include <array>


    class Magma {

    public:

        static const size_t byte_block_size = 8;

        static const size_t half_block_size = 4;

        static const size_t iter_keys_count = 32;

        Magma(const std::array<uint8_t, byte_block_size * 4>& key);

        Magma();

        void encrypt(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst);

        void decrypt(const std::array<uint8_t, byte_block_size>& src, std::array<uint8_t, byte_block_size>& dst);

        std::array<std::array<uint8_t, byte_block_size / 2>, iter_keys_count> get_iter_keys();

        void refresh_iter_keys(const std::array<uint8_t, byte_block_size * 4>& new_key);

        friend class MagmaTest;

    private:

        static const std::vector<std::vector<uint8_t >> pi;

        std::array<std::array<uint8_t, half_block_size>, iter_keys_count> iter_keys_;

        void k_expand(const std::array<uint8_t, byte_block_size * 4>& key);

        void t_transform(const std::array<uint8_t, half_block_size>& src, std::array<uint8_t, 4>& dst);

        void g_transform(const std::array<uint8_t, half_block_size>& src,
            const std::array<uint8_t, half_block_size>& key,
            std::array<uint8_t, half_block_size>& dst);

        void G_transform(const std::array<uint8_t, half_block_size>& a1_src,
            const std::array<uint8_t, half_block_size>& a0_src,
            const std::array<uint8_t, half_block_size>& key,
            std::array<uint8_t, half_block_size>& a1_dst,
            std::array<uint8_t, half_block_size>& a0_dst);

        void G_star_transform(const std::array<uint8_t, half_block_size>& a1_src,
            const std::array<uint8_t, half_block_size>& a0_src,
            const std::array<uint8_t, half_block_size>& key,
            std::array<uint8_t, byte_block_size>& dst);
    };

#endif //REFERENCEIMPLEMENTATIONS_MAGMA_H
