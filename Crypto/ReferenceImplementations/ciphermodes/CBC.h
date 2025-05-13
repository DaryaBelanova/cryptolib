#ifndef REFERENCEIMPLEMENTATIONS_CBC_H
#define REFERENCEIMPLEMENTATIONS_CBC_H

#include <vector>
#include <array>
#include <cstdint>


    /*
    * Предполагается, что расшифрованное дополненное сообщение будет урезаться внешним пользователем.
    */

    template <typename CipherType>
    class CBC {

    public:

        // must be called for every new message (not for a part of a message being sent).
        // this method does not reinitialize class fields but only refreshes them with new values
        void refresh_iv(const std::vector<uint8_t>& iv) {
            std::copy(iv.begin(), iv.end(), iv_.begin());
            std::copy(iv.begin(), iv.end(), curr_register_.begin());
        }

        CBC(CipherType& alg, std::vector<uint8_t> iv) : algorithm_(alg) {
            // initialization of all fields with required size
            iv_.resize(iv.size());
            curr_register_.resize(iv.size());

            // fill all fields with passed value
            refresh_iv(iv);
        }

        void encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        void decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        friend class CBCTest;

    private:

        std::vector<uint8_t> iv_;

        std::vector<uint8_t> curr_register_;

        CipherType algorithm_;
    };


    template<typename CipherType>
    void CBC<CipherType>::encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        if (src.empty()) {
            return;
        }

        std::vector<uint8_t> tmp(src.size());
        std::copy(src.begin(), src.end(), tmp.begin());

        while (tmp.size() % CipherType::byte_block_size != 0) {
            tmp.push_back(0x00);
        }

        std::array<uint8_t, CipherType::byte_block_size> curr_block = {};
        dst.resize(tmp.size());
        for (size_t i = 0; i < tmp.size(); i += CipherType::byte_block_size) {
            std::copy(tmp.begin() + i, tmp.begin() + i + CipherType::byte_block_size, curr_block.begin());
            for (int j = 0; j < CipherType::byte_block_size; j++) {
                curr_block[j] ^= curr_register_[j];
            }
            algorithm_.encrypt(curr_block, curr_block);
            // std::shift_left is unavailable until c++ 20
            // shift current register to left on n positions
            std::rotate(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_register_.end());
            // right n bytes rewrite with new gamma
            std::copy(curr_block.begin(), curr_block.end(), curr_register_.end() - CipherType::byte_block_size);

            std::copy(curr_block.begin(), curr_block.end(), dst.begin() + i);
        }
    }


    template<typename CipherType>
    void CBC<CipherType>::decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        if (src.empty()) {
            return;
        }

        std::vector<uint8_t> tmp_src(src.size());
        std::copy(src.begin(), src.end(), tmp_src.begin());

        std::array<uint8_t, CipherType::byte_block_size> curr_block = {};
        dst.resize(tmp_src.size());
        for (int i = 0; i < tmp_src.size(); i += CipherType::byte_block_size) {
            std::copy(tmp_src.begin() + i, tmp_src.begin() + i + CipherType::byte_block_size, curr_block.begin());
            algorithm_.decrypt(curr_block, curr_block);
            for (int i = 0; i < CipherType::byte_block_size; i++) {
                curr_block[i] ^= curr_register_[i];
            }
            std::rotate(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_register_.end());
            std::copy(tmp_src.begin() + i, tmp_src.begin() + i + CipherType::byte_block_size, curr_register_.end() - CipherType::byte_block_size);

            std::copy(curr_block.begin(), curr_block.end(), dst.begin() + i);
        }
    }

#endif //REFERENCEIMPLEMENTATIONS_CBC_H