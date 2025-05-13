#ifndef REFERENCEIMPLEMENTATIONS_CFB_H
#define REFERENCEIMPLEMENTATIONS_CFB_H

#include <vector>
#include <array>
#include <cstdint>
#include <algorithm>


/*
* Принимается, что гамма вырабатывается блоками длины равной длине блока открытого текста
  (равна длине блока шифрования для любого блока открытого текста, кроме, может быть, последнего, который может быть меньше)
*/

    template <typename CipherType>
    class CFB {

    public:

        // must be called for every new message (not for a part of a message being sent).
        // this method does not reinitialize class fields but only refreshes them with new values
        void refresh_iv(const std::vector<uint8_t>& iv) {
            curr_unused_gamma_idx_ = 0;
            std::copy(iv.begin(), iv.end(), iv_.begin());
            std::copy(iv.begin(), iv.end(), curr_register_.begin());
            // necessary for gamma initialization for first block processing of plaintext
            curr_unused_gamma_idx_ = CipherType::byte_block_size;
        }


        CFB(CipherType& alg, const std::vector<uint8_t>& iv) : algorithm_(alg) {
            // initialization of all fields with required size
            iv_.resize(iv.size());
            curr_register_.resize(iv.size());
            curr_gamma_ = {};

            // fill all fields with passed value
            refresh_iv(iv);
        }

        void encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        void decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        friend class CFBTest;

    private:

        size_t s_;
        std::vector<uint8_t> iv_;

        std::vector<uint8_t> curr_register_;
        std::array<uint8_t, CipherType::byte_block_size> curr_gamma_;
        size_t curr_unused_gamma_idx_;

        CipherType algorithm_;
    };

    template<typename CipherType>
    void CFB<CipherType>::encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        if (src.empty()) {
            return;
        }

        /*
        * ГОСТ 2034-13-2015 стр.18 п.5.5 абз.2
        * Реализовано: сообщение не дополняется ни в каких случаях.
        * Работает, как режим CTR: s (размер блока гаммы) берется равным размеру блока шифрования,
        * кроме, может быть, последнего, если блок исходного сообщения меньше
        * (тогда берется часть гаммы, равная последнему блоку сообщения, а оставшаяся часть сохраняется
        * для дальнейшего использования))
        */

        std::vector<uint8_t> tmp_src(src.size());
        std::copy(src.begin(), src.end(), tmp_src.begin());

        std::vector<uint8_t> curr_src_block = {};
        dst = {};
        dst.resize(tmp_src.size());
        for (int i = 0; i < tmp_src.size(); i += CipherType::byte_block_size) {
            auto end_of_block = (i + CipherType::byte_block_size < tmp_src.size()) ?
                tmp_src.begin() + i + CipherType::byte_block_size :
                tmp_src.end();

            curr_src_block.resize(std::min(tmp_src.size(), i + CipherType::byte_block_size) - i);
            std::copy(tmp_src.begin() + i, end_of_block, curr_src_block.begin());

            // if current gamma is used at all
            if (curr_unused_gamma_idx_ == CipherType::byte_block_size) {
                curr_unused_gamma_idx_ = 0;
                // copy new first n bytes of current register - gamma before encryption
                std::copy(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_gamma_.begin());
                // encrypt gamma
                algorithm_.encrypt(curr_gamma_, curr_gamma_);
            }
            for (int j = 0; j < curr_src_block.size(); ++j) {
                curr_src_block[j] ^= curr_gamma_[curr_unused_gamma_idx_++];
            }
            // std::shift_left is unavailable until c++ 20
            // shift current register to left on n positions
            std::rotate(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_register_.end());
            // right curr_src_block.size() bytes rewrite with ciphertext
            for (int j = 0; j < curr_src_block.size(); ++j) {
                curr_register_[curr_register_.size() - curr_src_block.size() + j] = curr_src_block[j];
            }

            std::copy(curr_src_block.begin(), curr_src_block.end(), dst.begin() + i);
        }
    }

    template<typename CipherType>
    void CFB<CipherType>::decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        if (src.empty()) {
            return;
        }

        std::vector<uint8_t> tmp_src(src.size());
        std::copy(src.begin(), src.end(), tmp_src.begin());

        std::vector<uint8_t> curr_src_block = {};
        dst = {};
        dst.resize(tmp_src.size());
        for (int i = 0; i < tmp_src.size(); i += CipherType::byte_block_size) {
            auto end_of_block = (i + CipherType::byte_block_size < tmp_src.size()) ?
                tmp_src.begin() + i + CipherType::byte_block_size :
                tmp_src.end();

            curr_src_block.resize(std::min(tmp_src.size(), i + CipherType::byte_block_size) - i);
            std::copy(tmp_src.begin() + i, end_of_block, curr_src_block.begin());

            // if current gamma is used at all
            if (curr_unused_gamma_idx_ == CipherType::byte_block_size) {
                curr_unused_gamma_idx_ = 0;
                // copy new first n bytes of current register - gamma before encryption
                std::copy(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_gamma_.begin());
                // encrypt gamma
                algorithm_.encrypt(curr_gamma_, curr_gamma_);
            }

            // std::shift_left is unavailable until c++ 20
            // shift current register to left on n positions
            std::rotate(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_register_.end());
            // right curr_src_block.size() bytes rewrite with ciphertext
            for (int j = 0; j < curr_src_block.size(); ++j) {
                curr_register_[curr_register_.size() - curr_src_block.size() + j] = curr_src_block[j];
                curr_src_block[j] ^= curr_gamma_[curr_unused_gamma_idx_++];
            }

            std::copy(curr_src_block.begin(), curr_src_block.end(), dst.begin() + i);
        }
    }



#endif //REFERENCEIMPLEMENTATIONS_CFB_H
