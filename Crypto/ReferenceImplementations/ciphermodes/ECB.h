#ifndef REFERENCEIMPLEMENTATIONS_ECB_H
#define REFERENCEIMPLEMENTATIONS_ECB_H

#include <cstdint>
#include <vector>
#include <array>

    /*
    * Предполагается, что расшифрованное дополненное сообщение будет урезаться внешним пользователем.
    */

    template <typename CipherType>
    class ECB {

    public:

        ECB(CipherType& alg) : algorithm_(alg) {
        }

        void encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);


        void decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        friend class ECBTest;

    private:

        CipherType algorithm_;
    };

    template<typename CipherType>
    void ECB<CipherType>::encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        if (src.empty()) {
            return;
        }

        std::vector<uint8_t> tmp(src.size());
        std::copy(src.begin(), src.end(), tmp.begin());

        while (tmp.size() % CipherType::byte_block_size != 0) {
            tmp.push_back(0x00);
        }

        std::array<uint8_t, CipherType::byte_block_size> curr_block = {};
        dst = {};
        dst.resize(tmp.size());
        for (size_t i = 0; i < tmp.size(); i += CipherType::byte_block_size) {
            std::copy(tmp.begin() + i, tmp.begin() + i + CipherType::byte_block_size, curr_block.begin());
            algorithm_.encrypt(curr_block, curr_block);
            std::copy(curr_block.begin(), curr_block.end(), dst.begin() + i);
        }
    }

    template<typename CipherType>
    void ECB<CipherType>::decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        std::vector<uint8_t> tmp_src(src.size());
        std::copy(src.begin(), src.end(), tmp_src.begin());

        std::array<uint8_t, CipherType::byte_block_size> curr_block = {};
        dst = {};
        dst.resize(src.size());
        for (int i = 0; i < tmp_src.size(); i += CipherType::byte_block_size) {
            std::copy(tmp_src.begin() + i, tmp_src.begin() + i + CipherType::byte_block_size, curr_block.begin());
            algorithm_.decrypt(curr_block, curr_block);

            std::copy(curr_block.begin(), curr_block.end(), dst.begin() + i);
        }
    }

#endif //REFERENCEIMPLEMENTATIONS_ECB_H
