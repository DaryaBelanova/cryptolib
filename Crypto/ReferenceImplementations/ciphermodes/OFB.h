#ifndef REFERENCEIMPLEMENTATIONS_OFB_H
#define REFERENCEIMPLEMENTATIONS_OFB_H

#include <vector>
#include <cstdint>
#include <algorithm>


    template<typename CipherType>
    class OFB {

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

        OFB(CipherType& alg, const std::vector<uint8_t>& iv) : algorithm_(alg) {
            // initialization of all fields with required size
            iv_.resize(iv.size());
            curr_register_.resize(iv.size());
            curr_gamma_ = {};

            // fill all fields with passed value
            refresh_iv(iv);
        }

        void encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);


        void decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst);

        friend class OFBTest;

    private:

        std::vector<uint8_t> iv_;

        std::vector<uint8_t> curr_register_;
        std::array<uint8_t, CipherType::byte_block_size> curr_gamma_;
        size_t curr_unused_gamma_idx_;

        CipherType algorithm_;
    };


    template<typename CipherType>
    void OFB<CipherType>::encrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
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
                // std::shift_left is unavailable until c++ 20
                // shift current register to left on n positions
                std::rotate(curr_register_.begin(), curr_register_.begin() + CipherType::byte_block_size, curr_register_.end());
                // right n bytes rewrite with new gamma
                for (int j = 0; j < CipherType::byte_block_size; ++j) {
                    curr_register_[curr_register_.size() - CipherType::byte_block_size + j] = curr_gamma_[j];
                }
            }

            for (int j = 0; j < curr_src_block.size(); ++j) {
                curr_src_block[j] ^= curr_gamma_[curr_unused_gamma_idx_++];
            }

            std::copy(curr_src_block.begin(), curr_src_block.end(), dst.begin() + i);
        }
    }

    template<typename CipherType>
    void OFB<CipherType>::decrypt(const std::vector<uint8_t>& src, std::vector<uint8_t>& dst) {
        encrypt(src, dst);
    }


#endif //REFERENCEIMPLEMENTATIONS_OFB_H
