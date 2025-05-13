#ifndef REFERENCEIMPLEMENTATIONS_CMAC_H
#define REFERENCEIMPLEMENTATIONS_CMAC_H

#include <vector>
#include <array>
#include <cstdint>


    /*
    * Параметр s передается только в режиме имитовставки. В остальных режимах, где он имеется по ГОСТу,
    * он игноируется ввиду полагания в жизни его равным блоку шифрования с оговоркой, что последний блок
    * может быть меньше
    */

    template <typename CipherType>
    class CMAC {

    public:

        //CMAC(CipherType& alg, size_t s) : algorithm_(alg), s_(s / 8), last_block_size_(0) { // s (in bits) is expected to be a multiple of 8
        //    
        //    //initializing of inner state
        //    curr_state = {};
        //}

        CMAC(CipherType& alg, /*const std::array<uint8_t, 32>& key,*/ size_t s) : algorithm_(alg), s_(s / 8) { // s (in bits) is expected to be a multiple of 8

            //initializing of inner state
            last_block_size_ = 0;
            curr_state = {};
        }

        // refresh inner state with new block of plaintext
        void update(const std::vector<uint8_t>& src);

        // Xor padding to curr_state copy if last_block_size_ is less than cipher block size then
        // xor key to curr_state copy and
        // calculate mac for curr_state copy. Does not change curr_state
        void finalize(std::vector<uint8_t>& dst);

        // set new value for s_ and reset all inner state
        void refresh(size_t s);

        /* finalize
         * and compare calculated mac with passed parameter
         */
        bool verify(const std::vector<uint8_t>& mac);

        friend class CMACTest;

    private:

        CipherType algorithm_;

        size_t last_block_size_;

        // previous state with xored last block
        std::array<uint8_t, CipherType::byte_block_size> curr_state;

        // mac length in bytes
        size_t s_;

        void get_k1(std::array<uint8_t, CipherType::byte_block_size>& dst);

        void get_k2(std::array<uint8_t, CipherType::byte_block_size>& dst);
    };

    template<typename CipherType>
    void CMAC<CipherType>::get_k1(std::array<uint8_t, CipherType::byte_block_size>& dst) {
        std::array<uint8_t, CipherType::byte_block_size> k = {};
        algorithm_.encrypt(k, k);
        dst.fill(0);
        for (size_t i = 0; i < CipherType::byte_block_size; i++) {
            dst[i] = (k[i % CipherType::byte_block_size] << 1) |
                (k[(i + 1) % CipherType::byte_block_size] >> 7);
        }
        dst[CipherType::byte_block_size - 1] &= 0b11111110;

        if (k[0] & 0x80) {
            if (CipherType::byte_block_size == 8) {
                dst[CipherType::byte_block_size - 1] ^= 0b00011011;
            }
            else if (CipherType::byte_block_size == 16) {
                dst[CipherType::byte_block_size - 1] ^= 0b10000111;
            }
            else {
                // not supported
            }
        }
    }

    template<typename CipherType>
    void CMAC<CipherType>::get_k2(std::array<uint8_t, CipherType::byte_block_size>& dst) {
        std::array<uint8_t, CipherType::byte_block_size> k = {};
        get_k1(k);
        dst.fill(0);
        for (size_t i = 0; i < CipherType::byte_block_size; i++) {
            dst[i] = (k[i % CipherType::byte_block_size] << 1) |
                (k[(i + 1) % CipherType::byte_block_size] >> 7);
        }
        dst[CipherType::byte_block_size - 1] &= 0b11111110;

        if (k[0] & 0x80) {
            if (CipherType::byte_block_size == 8) {
                dst[CipherType::byte_block_size - 1] ^= 0b00011011;
            }
            else if (CipherType::byte_block_size == 16) {
                dst[CipherType::byte_block_size - 1] ^= 0b10000111;
            }
            else {
                // not supported
            }
        }
    }

    template<typename CipherType>
    void CMAC<CipherType>::update(const std::vector<uint8_t>& src) {
        if (src.empty()) {
            return;
        }

        std::vector<uint8_t> tmp(src.size());
        std::copy(src.begin(), src.end(), tmp.begin());

        int curr_idx;
        if (last_block_size_ == CipherType::byte_block_size) {
            algorithm_.encrypt(curr_state, curr_state);
            curr_idx = 0;
            last_block_size_ = 0;
        }
        else {
            curr_idx = last_block_size_;
        }

        for (int i = 0; i < tmp.size(); ++i) {
            if (curr_idx == CipherType::byte_block_size) {
                algorithm_.encrypt(curr_state, curr_state);
                last_block_size_ = 0;
                curr_idx = 0;
            }
            curr_state[curr_idx] ^= tmp[i];
            ++curr_idx;
            ++last_block_size_;
        }
    }

    // this method does not change curr_state
    template<typename CipherType>
    void CMAC<CipherType>::finalize(std::vector<uint8_t>& dst) {
        std::array<uint8_t, CipherType::byte_block_size> k = {};

        std::array<uint8_t, CipherType::byte_block_size> curr_state_copy = {};
        std::copy(curr_state.begin(), curr_state.end(), curr_state_copy.begin());
        if (last_block_size_ < CipherType::byte_block_size) {
            curr_state_copy[last_block_size_] ^= 0x80; // P||1|00..0 -> P||10000000||....
            get_k2(k);
        }
        else {
            get_k1(k);
        }

        for (int i = 0; i < CipherType::byte_block_size; ++i) {
            curr_state_copy[i] ^= k[i];
        }
        algorithm_.encrypt(curr_state_copy, curr_state_copy);

        dst.resize(s_);
        std::copy(curr_state_copy.begin(), curr_state_copy.begin() + s_, dst.begin());
    }

    template<typename CipherType>
    void CMAC<CipherType>::refresh(size_t s) {
        s_ = s / 8;

        curr_state.fill(0);
        last_block_size_ = 0;
    }

    template<typename CipherType>
    bool CMAC<CipherType>::verify(const std::vector<uint8_t>& mac) {
        // with empty, non-empty with empty, empty with non-empty -> false
        if (curr_state.empty() || mac.empty()) {
            return false;
        }

        std::vector<uint8_t> calculated;
        finalize(calculated);
        calculated.resize(s_);

        return calculated == mac;
    }


#endif //REFERENCEIMPLEMENTATIONS_CMAC_H